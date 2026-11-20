// Deterministic SVG rendering for the Petra films. No browser or external generation.
// npm ci --prefix docs/media/renderer
// node docs/media/build-vectors.mjs docs/media/models [--stills]
import {Resvg} from './renderer/node_modules/@resvg/resvg-js/index.js';
import {readFileSync,writeFileSync,mkdtempSync,renameSync,rmSync} from 'node:fs';
import {execFileSync,spawn} from 'node:child_process';
import {resolve,join} from 'node:path';
import {tmpdir} from 'node:os';
import vm from 'node:vm';
const dir=resolve(process.argv[2]);
const stills=process.argv.includes('--stills');
const spec=JSON.parse(readFileSync(join(dir,'script.json'),'utf8'));
const fps=spec.fps??25;
const work=mkdtempSync(join(tmpdir(),'gate-premium-'));
const run=(cmd,args)=>execFileSync(cmd,args,{encoding:'utf8',stdio:['ignore','pipe','pipe']}).trim();
let start=0;
const times=spec.scenes.map((s,i)=>{
 const voice=join(dir,'voice',`${String(i).padStart(2,'0')}-${s.id}.m4a`), clip=join(work,`${i}.wav`);
 const trim='silenceremove=start_periods=1:start_threshold=-45dB';
 run('ffmpeg',['-y','-v','error','-i',voice,'-af',`${trim},areverse,${trim},areverse,atempo=${spec.tempo}`,clip]);
 const len=Number(run('ffprobe',['-v','error','-show_entries','format=duration','-of','csv=p=0',clip]));
 const dur=Math.ceil((len+spec.padSeconds)*fps)/fps;
 const t={id:s.id,start,dur};start+=dur;return {...t,audio:clip};
});
const source=join(dir,spec.output);
const inputs=times.flatMap(t=>['-i',t.audio]);
const pads=times.map((t,i)=>`[${i}:a]aresample=48000,apad=whole_dur=${t.dur}[a${i}]`).join(';');
const cat=times.map((_,i)=>`[a${i}]`).join('')+`concat=n=${times.length}:v=0:a=1[out]`;
const narration=join(work,'narration.m4a');
run('ffmpeg',['-y','-v','error',...inputs,'-filter_complex',`${pads};${cat}`,'-map','[out]','-c:a','aac','-b:a','160k',narration]);
const stamp=t=>{let ms=Math.round(t*1000);const h=Math.floor(ms/3600000);ms%=3600000;const m=Math.floor(ms/60000);ms%=60000;const s=Math.floor(ms/1000);return `${String(h).padStart(2,'0')}:${String(m).padStart(2,'0')}:${String(s).padStart(2,'0')}.${String(ms%1000).padStart(3,'0')}`;};
const captions=['WEBVTT',''];
for(let i=0;i<times.length;i++){
 const t=times[i], words=spec.scenes[i].spoken.split(' '), chunks=[];
 for(let w=0;w<words.length;w+=11)chunks.push(words.slice(w,w+11).join(' '));
 const speaking=t.dur-spec.padSeconds;
 chunks.forEach((line,j)=>captions.push(`${stamp(t.start+speaking*j/chunks.length)} --> ${stamp(t.start+speaking*(j+1)/chunks.length)}`,line,''));
}
writeFileSync(join(dir,'captions.en.vtt'),captions.join('\n'));
writeFileSync(join(dir,'timings.json'),JSON.stringify(times.map(({audio,...t})=>t),null,2));
const tokens=Object.fromEntries([...readFileSync(resolve('design/gate-brand.css'),'utf8').matchAll(/(--gate-[\w-]+)\s*:\s*([^;]+);/g)].map(m=>[m[1],m[2]]));
const root={innerHTML:''};
const sandbox={window:{__BUILD__:true},document:{documentElement:{},getElementById:()=>root},getComputedStyle:()=>({getPropertyValue:n=>tokens[n]||''}),console,Math};
const context=vm.createContext(sandbox);
const html=readFileSync(join(dir,'scenes.html'),'utf8');
if(html.includes('src="../kit.js"'))vm.runInContext(readFileSync(resolve('docs/media/kit.js'),'utf8'),context);
for(const script of html.matchAll(/<script(?:\s[^>]*)?>([\s\S]*?)<\/script>/g))if(script[1].trim())vm.runInContext(script[1],context);
context.window.setTimes(times);
const draw=t=>{context.window.frame(t);return root.innerHTML.replace('<svg ', '<svg style="font-family:Helvetica Neue,Arial,sans-serif" ');};
const render=t=>new Resvg(draw(t),{font:{loadSystemFonts:false,fontFiles:['/System/Library/Fonts/HelveticaNeue.ttc','/System/Library/Fonts/Menlo.ttc'],defaultFontFamily:'Helvetica Neue',sansSerifFamily:'Helvetica Neue',monospaceFamily:'Menlo'}}).render();
const posterTime=Math.min(times[0].dur*.72,9);
writeFileSync(join(dir,'poster.png'),render(posterTime).asPng());
run('ffmpeg',['-y','-v','error','-i',join(dir,'poster.png'),'-q:v','2',join(dir,'poster.jpg')]);
rmSync(join(dir,'poster.png'));
if(stills){
 for(const t of times)for(const f of [.35,.65,.9])writeFileSync(join(work,`${t.id}-${f}.png`),render(t.start+t.dur*f).asPng());
 writeFileSync(join(work,'timings.json'),JSON.stringify(times,null,2));
 console.log(JSON.stringify({stills:work,seconds:start,fps}));
}else{
 const pending=join(dir,spec.output.replace('.mp4','.pending.mp4'));
 const ff=spawn('ffmpeg',['-y','-v','error','-f','rawvideo','-pixel_format','rgba','-video_size','1920x1080','-framerate',String(fps),'-i','-','-i',narration,'-map','0:v:0','-map','1:a:0','-c:v','libx264','-threads','2','-preset','fast','-crf','23','-pix_fmt','yuv420p','-c:a','copy','-shortest','-movflags','+faststart',pending],{stdio:['pipe','ignore','inherit']});
 const done=new Promise((r,j)=>ff.once('close',c=>c===0?r():j(new Error(`ffmpeg ${c}`))));
 const count=Math.round(start*fps);
 for(let f=0;f<count;f++){
  if(!ff.stdin.write(render(f/fps).pixels))await new Promise(r=>ff.stdin.once('drain',r));
  if(f%250===0)console.log(`${dir.split('/').at(-1)} ${f}/${count}`);
 }
 ff.stdin.end();await done;
 run('ffmpeg',['-v','error','-i',pending,'-f','null','-']);
 const hash=file=>run('ffmpeg',['-v','error','-i',file,'-map','0:a:0','-c','copy','-f','hash','-hash','sha256','-']);
 if(hash(narration)!==hash(pending))throw new Error('Narration stream changed');
 renameSync(pending,source);rmSync(work,{recursive:true,force:true});console.log(JSON.stringify({output:source,seconds:start,fps,audio:'Petra narration, Qadamar intro/outro'}));
}
