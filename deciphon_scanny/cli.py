import asyncio
from pathlib import Path

import typer

from deciphon_scanny.scanny import create_scanny

app = typer.Typer()


@app.command()
def server():
    pass


@app.command()
def scan(scan_file: Path, db_file: Path):
    async def main():
        async with create_scanny(scan_file.name, db_file.name, True, False) as scanny:
            await scanny.wait()
        raise typer.Exit(scanny.result.value)

    asyncio.run(main())
