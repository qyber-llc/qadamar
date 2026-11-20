#!/usr/bin/env python3
"""Create a credential-free Qadamar delivery from this working-tree snapshot."""
from pathlib import Path
import json,subprocess,shutil,zipfile,hashlib,sys
r=Path(__file__).resolve().parents[2]
out=Path(sys.argv[1]).resolve() if len(sys.argv)>1 else r/'dist/qadamar-delivery'
out.mkdir(parents=True,exist_ok=True); root=out/'qadamar-delivery'; root.mkdir(exist_ok=True)
source=root/'qadamar-source'; source.mkdir(exist_ok=True)
paths=subprocess.check_output(['git','ls-files','-z','--cached','--others','--exclude-standard'],cwd=r).decode().split('\0')
for path in paths:
 if not path:continue
 p=Path(path)
 if any(part in {'.git','node_modules','__pycache__','data','.DS_Store','.lake'} for part in p.parts):continue
 if p.name.startswith('.env') and p.name!='.env.example':continue
 if p.suffix in {'.mp4','.wav'} or p.name.endswith('.pending.mp4'):continue
 f=r/p
 if f.is_file() and not f.is_symlink():
  d=source/p;d.parent.mkdir(parents=True,exist_ok=True);shutil.copy2(f,d)
shutil.copytree(r/'apps/admin/dist',source/'apps/admin/dist',dirs_exist_ok=True)
shutil.copytree(r/'website/dist',root/'website',dirs_exist_ok=True,ignore=lambda path,names:[n for n in names if Path(path).name=='downloads' and n!='delivery.html'])
shutil.copytree(r/'docs/brand',root/'branding',dirs_exist_ok=True)
shutil.copytree(r/'docs/infographic',root/'infographic',dirs_exist_ok=True)
(root/'delivery').mkdir(exist_ok=True)
shutil.copy2(r/'docs/DELIVERY.md',root/'START-HERE.md')
shutil.copy2(r/'docs/DELIVERY.md',root/'delivery/HANDOVER.md')
# Build identities describe exactly what was packaged, without claiming an upstream tag or clean checkout.
info={'product':'Qadamar','publisher':'Qyber LLC','version':'0.12.2','date':'2026-11-20','upstream_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=r).decode().strip(),'working_tree_snapshot':True,'signed_release':False,'excluded':['.git','node_modules','runtime state','credentials','.env files'],'code_license':'Apache-2.0'}
(root/'delivery/BUILD-INFO.json').write_text(json.dumps(info,indent=2)+'\n')
# The known verification report is prepared separately, including video and browser checks.
shutil.copy2(r/'docs/delivery-verification.json',root/'delivery/verification.json')
shutil.copy2(r/'docs/qadamar-sbom.cdx.json',root/'delivery/qadamar-sbom.cdx.json')
def archive(folder,target,prefix):
 with zipfile.ZipFile(target,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
  for f in sorted(folder.rglob('*')):
   if f.is_file() and not f.is_symlink():z.write(f,str(Path(prefix)/f.relative_to(folder)))
archive(source,out/'qadamar-source.zip','qadamar-source')
archive(root/'website',out/'qadamar-website.zip','website')
archive(root,out/'qadamar-delivery.zip','qadamar-delivery')
files=[out/'qadamar-source.zip',out/'qadamar-website.zip',out/'qadamar-delivery.zip']
(out/'SHA256SUMS').write_text(''.join(hashlib.sha256(f.read_bytes()).hexdigest()+'  '+f.name+'\n' for f in files))
print(json.dumps({'directory':str(root),'archives':[{'path':str(f),'bytes':f.stat().st_size} for f in files]},indent=2))
