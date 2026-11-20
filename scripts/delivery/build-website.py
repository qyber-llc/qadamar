#!/usr/bin/env python3
"""Assemble the static Qadamar site after the console and films have been built."""
from pathlib import Path
import shutil,subprocess
root=Path(__file__).resolve().parents[2]; out=root/'website/dist'; out.mkdir(parents=True,exist_ok=True)
for f in (root/'website/src').iterdir():
 if f.is_file():shutil.copy2(f,out/f.name)
 elif f.is_dir():shutil.copytree(f,out/f.name,dirs_exist_ok=True)
assets=out/'assets';assets.mkdir(exist_ok=True)
for f in (root/'docs/brand').glob('qadamar-*'):
 if f.suffix in ('.svg','.png','.json','.zip'):shutil.copy2(f,assets/f.name)
shutil.copy2(root/'docs/infographic/qadamar-access-infographic.svg',assets/'qadamar-access-infographic.svg')
for name in ['README.md','LICENSE','NOTICE','SECURITY.md','THIRD-PARTY-NOTICES.md']:
 shutil.copy2(root/name,assets/name)
for name in ['API.md','ARCHITECTURE.md','DEPLOY.md','CONFIGURATION.md','QUALITY.md','DELIVERY.md']:
 shutil.copy2(root/'docs'/name,assets/name)
for name in ['world.json','bundle.json']:shutil.copy2(root/'examples/qadamar-demo'/name,assets/name)
for film in ['models','sectors','usecases']:
 dest=out/'media'/film;dest.mkdir(parents=True,exist_ok=True)
 for name in ['qadamar-'+film+'.mp4','poster.jpg','captions.en.vtt']:
  shutil.copy2(root/'docs/media'/film/name,dest/name)
subprocess.run(['node','scripts/delivery/build-demo.ts'],cwd=root,check=True)
print(out)
