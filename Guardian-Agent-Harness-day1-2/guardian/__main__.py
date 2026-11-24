import argparse
import json
from pathlib import Path
from .store import Store
from .engine import run_scan
from .evaluation import evaluate


def main():
    parser=argparse.ArgumentParser(description='GuardianAI — supply-chain analysis and knowledge graph')
    parser.add_argument('--data',default='.guardian',help='Persistent memory directory')
    sub=parser.add_subparsers(dest='command',required=True)
    serve=sub.add_parser('serve'); serve.add_argument('--port',type=int,default=8787)
    scan=sub.add_parser('scan'); scan.add_argument('source'); scan.add_argument('--offline',action='store_true'); scan.add_argument('--planted',action='store_true'); scan.add_argument('--output')
    sub.add_parser('list'); sub.add_parser('eval')
    export=sub.add_parser('export'); export.add_argument('scan_id'); export.add_argument('--format',choices=['json','sbom','markdown'],default='json'); export.add_argument('--output')
    review=sub.add_parser('review'); review.add_argument('scan_id'); review.add_argument('finding_id'); review.add_argument('status',choices=['open','confirmed','false positive','accepted']); review.add_argument('--actor',required=True); review.add_argument('--reason',required=True)
    baseline=sub.add_parser('baseline'); baseline.add_argument('scan_id'); baseline.add_argument('--actor',required=True); baseline.add_argument('--reason',required=True)
    lesson=sub.add_parser('approve-lesson'); lesson.add_argument('lesson_id',type=int); lesson.add_argument('--actor',required=True); lesson.add_argument('--reason',required=True)
    args=parser.parse_args(); store=Store(args.data)
    try:
        if args.command=='serve':
            from .server import serve
            serve(store,port=args.port); return
        if args.command=='scan': result=run_scan(args.source,store,args.offline,args.planted)
        elif args.command=='list': result=store.list()
        elif args.command=='eval': result=evaluate()
        elif args.command=='review': store.review(args.scan_id,args.finding_id,args.status,args.actor,args.reason); result={'ok':True}
        elif args.command=='baseline': store.promote(args.scan_id,args.actor,args.reason); result={'ok':True}
        elif args.command=='approve-lesson': store.approve_lesson(args.lesson_id,args.actor,args.reason); result={'ok':True}
        else:
            result=store.get(args.scan_id)
            if args.format=='sbom': result=result['sbom']
            elif args.format=='markdown':
                rows=['# GuardianAI security report',f'Repository: {result["repo"]}',f'Scan: {result["id"]} · {result["created"]}',f'Inventory: {result["coverage"]["inventory"]}; vulnerability coverage: {result["coverage"]["vulnerability_status"]}',f'Planted demo: {result["planted"]}']
                for f in result['findings']:
                    rows += [f'## {f["risk_level"]}: {f["what"]}',f'Status: {f["status"]}; confidence: {f["confidence"]}',f'Component: {f["component"]}',f'Path: {" → ".join(f["dependency_path"]) or "Unresolved"}',f'Evidence: {json.dumps(f["verified_evidence"],ensure_ascii=False)}',f'Score: {f["score_explanation"]}']
                rows += ['## Limitations',*result['limitations'],*result['coverage']['warnings']]
                result='\n\n'.join(rows)
        output=result if isinstance(result,str) else json.dumps(result,indent=2,ensure_ascii=False)
        if getattr(args,'output',None): Path(args.output).write_text(output)
        else: print(output)
        if args.command=='eval' and not result['passed']: raise SystemExit(1)
    except (ValueError,OSError) as exc: parser.exit(1,f'Error: {exc}\n')


if __name__=='__main__': main()
