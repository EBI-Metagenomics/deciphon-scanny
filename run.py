import json
import os
import shutil
import tarfile
import threading
from functools import lru_cache
from subprocess import PIPE, Popen

import requests
from kombu import Connection, Exchange, Queue
from pydantic import BaseSettings
from requests_toolbelt.multipart import encoder
from requests_toolbelt.multipart.encoder import MultipartEncoderMonitor

BIN = "/Users/horta/code/deciphon-scanny/deciphon_scanny/scanny-mac"


class Config(BaseSettings):
    api_host: str = "127.0.0.1"
    api_port: int = 8000
    api_prefix: str = ""
    api_key: str = "change-me"
    verbose: bool = False

    class Config:
        env_file = ".env"
        env_file_encoding = "utf-8"
        validate_assignment = True

    @property
    def api_url(self):
        return f"http://{self.api_host}:{self.api_port}{self.api_prefix}"


@lru_cache
def get_config() -> Config:
    return Config()


config = get_config()


def fire_and_forget(f):
    def wrapped():
        threading.Thread(target=f).start()

    return wrapped


def url(path: str) -> str:
    return f"{config.api_url}{path}"


def make_tarfile(output_filename, source_dir):
    with tarfile.open(output_filename, "w:gz") as tar:
        tar.add(source_dir, arcname=os.path.basename(source_dir))


chunk_size = 64 * 1024


def patch(path: str):
    hdrs = {
        "Accept": "application/json",
        "X-API-KEY": config.api_key,
    }
    try:
        return requests.patch(url(path), headers=hdrs)
    except ConnectionError as conn_error:
        print(conn_error)


def press_scan(seqs_file: str, db_file: str, job_id: int):
    proc = Popen([BIN, seqs_file, db_file], stdout=PIPE)
    assert proc.stdout
    last_progress = 0
    for raw_line in proc.stdout:
        line = raw_line.decode().strip()
        if line == "done":
            print(line)
        elif line == "fail":
            print(line)
        else:
            cur_progress = int(line.replace("%", ""))
            if cur_progress > last_progress:
                inc = cur_progress - last_progress

                @fire_and_forget
                def send_update():
                    patch(f"/jobs/{job_id}/progress/increment/{inc}")

                send_update()
                last_progress = cur_progress
                print(cur_progress)

    exit_code = proc.wait()
    print(f"exitcode: {exit_code}")


def download(path: str, filename: str):
    hdrs = {
        "Accept": "*/*",
        "X-API-KEY": config.api_key,
    }
    with requests.get(url(path), stream=True, headers=hdrs) as r:
        r.raise_for_status()
        with open(filename, "wb") as f:
            for chunk in r.iter_content(chunk_size=chunk_size):
                # filter out keep-alive new chunks
                if chunk:
                    f.write(chunk)


def get(url: str, content_type: str, params=None) -> requests.Response:
    hdrs = {
        "Accept": "application/json",
        "Content-Type": content_type,
        "X-API-KEY": config.api_key,
    }
    return requests.get(url, params=params, headers=hdrs)


def get_json(path: str, params=None) -> str:
    return get(path, "application/json", params).json()


class UploadProgress:
    def __init__(self, total_bytes: int, filename: str):
        # self._bar = tqdm_file(total_bytes, filename)
        self._bytes_read = 0

    def __enter__(self):
        return self

    def __exit__(self, *args):
        del args
        # self._bar.close()

    def __call__(self, monitor: MultipartEncoderMonitor):
        increment = monitor.bytes_read - self._bytes_read
        # self._bar.update(increment)
        self._bytes_read += increment


def upload(path: str, field_name: str, filepath: str, mime: str) -> str:
    e = encoder.MultipartEncoder(
        fields={
            field_name: (
                filepath,
                open(filepath, "rb"),
                mime,
            )
        }
    )
    with UploadProgress(e.len, filepath) as up:
        monitor = encoder.MultipartEncoderMonitor(e, up)
        hdrs = {
            "Accept": "application/json",
            "Content-Type": monitor.content_type,
            "X-API-KEY": config.api_key,
        }
        r = requests.post(
            url(path),
            data=monitor,  # type: ignore
            headers=hdrs,
        )
        # r.raise_for_status()
    return r.json()
    # return pretty_json(r.json())


def process_request(scan, message):
    try:
        print(scan)
        scan_id = scan["id"]
        hmm_id = scan["hmm_id"]
        hmm_file = scan["hmm_file"]
        db_id = scan["db_id"]
        db_file = scan["db_file"]
        job_id = scan["job_id"]
        # multi_hits = scan["multi_hits"]
        # hmmer3_compat = scan["hmmer3_compat"]

        try:
            shutil.rmtree("prod")
        except Exception as e:
            print(e)

        try:
            os.unlink("prod.tar.gz")
        except Exception as e:
            print(e)

        seqs_json = get_json(url(f"/scans/{scan_id}/seqs"))
        with open("seqs.json", "w") as f:
            f.write(json.dumps(seqs_json))

        patch(f"/jobs/{job_id}/set-run")

        download(f"/hmms/{hmm_id}/download", hmm_file)
        print("Download HMM finished")

        download(f"/dbs/{db_id}/download", db_file)
        print("Download DB finished")

        press_scan("seqs.json", db_file, job_id)
        make_tarfile("prod.tar.gz", "prod")

        mime = "application/gzip"
        upload(
            f"/scans/{scan_id}/prods/",
            "prod_file",
            "prod.tar.gz",
            mime,
        )
        message.ack()
    except Exception as e:
        message.ack()
        print(e)


def create_server():
    exchange = Exchange("scan", "direct", durable=True)
    queue = Queue("scan", exchange=exchange, routing_key="scan")
    with Connection("amqp://guest:guest@localhost//") as conn:
        with conn.Consumer(queue, callbacks=[process_request]) as consumer:
            while True:
                conn.drain_events()


create_server()
