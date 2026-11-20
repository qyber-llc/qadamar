import {readFileSync,writeFileSync,rmSync} from 'node:fs';
import {evaluate,indexTuples,type PolicyBundle,type Subject,type Resource,type Tuple} from '../../packages/core/src/index.ts';
const world=JSON.parse(readFileSync('examples/qadamar-demo/world.json','utf8')) as {now:string;subjects:Subject[];resources:Resource[];tuples:Tuple[]};
const bundle=JSON.parse(readFileSync('examples/qadamar-demo/bundle.json','utf8')) as PolicyBundle;
const subject=world.subjects.find(s=>s.id==='amira')!, resource=world.resources.find(r=>r.id==='CASE-7')!;
const scenarios=[];
for(const action of ['read','export','update'])for(const network of ['trusted','untrusted'] as const){
 const request={subject,resource,action,context:{network,now:world.now}};
 scenarios.push({action,network,request,output:evaluate(bundle,request,indexTuples(world.tuples))});
}
writeFileSync('website/dist/assets/demo-results.json',JSON.stringify({generatedAt:new Date().toISOString(),fixtureTime:world.now,source:'packages/core/src/evaluate.ts',kind:'precomputed-engine-fixtures',scenarios},null,2));
rmSync('website/dist/assets/engine',{recursive:true,force:true});
console.log(scenarios.map(s=>`${s.action}/${s.network}: ${s.output.decision?'ALLOW':'DENY'} ${s.output.rules.join(',')}`).join('\n'));
