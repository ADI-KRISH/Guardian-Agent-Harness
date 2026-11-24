"""Conservative, bounded source-to-network argument matching (not full dataflow analysis)."""
import re

# Environment configuration is not a secret by itself.
BENIGN={'NODE_ENV','PORT','HOST','OSTYPE','PLATFORM','CI','DEBUG','HOME','PATH','PWD','TMPDIR','TZ','LANG','LOG_LEVEL'}
ENV=re.compile(r'process\.env(?:\.([A-Za-z_$][\w$]*)|\[\s*[\'"]([^\'"]+)[\'"]\s*\])?|os\.environ(?:\[\s*[\'"]([^\'"]+)[\'"]\s*\]|\.get\(\s*[\'"]([^\'"]+)[\'"])|(?:os\.getenv|System\.getenv|Environment\.GetEnvironmentVariable)\(\s*[\'"]([^\'"]+)[\'"]')
SINK=re.compile(r'\b(?:fetch|(?:axios|requests|httpx)\.(?:post|put|patch|request)|(?:https?|client)\.request|navigator\.sendBeacon)\s*\(')


def code_only(text):
    # Preserve offsets and line numbers. Remove comments, keeping string literals for literal targets and env keys.
    pattern=re.compile(r'([\'"])(?:\\.|(?!\1).)*?\1|//[^\n]*|/\*[\s\S]*?\*/|(?m:^[ \t]*\#[^\n]*)')
    return pattern.sub(lambda m: m[0] if m[0].startswith(('"',"'")) else re.sub(r'[^\n]',' ',m[0]),text)


def call_end(text,start,limit=2000):
    depth=1;quote=None;escape=False
    for i in range(start,min(len(text),start+limit)):
        c=text[i]
        if quote:
            if escape:escape=False
            elif c=='\\':escape=True
            elif c==quote:quote=None
        elif c in ('"',"'",'`'):quote=c
        elif c=='(':depth+=1
        elif c==')':
            depth-=1
            if depth==0:return i
    return min(len(text),start+limit)


def sensitive_sources(text):
    for m in ENV.finditer(text):
        name=next((g for g in m.groups() if g),None)
        if name in BENIGN:continue
        # Named values must resemble secrets; whole-environment serialization is also sensitive.
        if name and not re.search(r'TOKEN|SECRET|PASSWORD|PASSWD|API_?KEY|CREDENTIAL|PRIVATE_?KEY|AUTH',name,re.I):continue
        yield m
    for m in re.finditer(r'(?:readFileSync|readFile|open)\s*\([^\n)]*(?:\.npmrc|\.ssh/|\.aws/credentials)',text):yield m


def exfiltration_flows(text):
    code=code_only(text);out=[]
    for sink in SINK.finditer(code):
        end=call_end(code,sink.end());args=code[sink.end():end]
        sources=list(sensitive_sources(args));via=None;source_offset=None
        if sources:source_offset=sink.end()+sources[0].start()
        else:
            # Follow a direct local assignment only within 8 preceding lines, with no reassignment.
            start=max(0,code.rfind('\n',0,max(0,sink.start()-1500)))
            prefix=code[start:sink.start()];lines=prefix.splitlines(keepends=True)[-8:];prefix=''.join(lines);start=sink.start()-len(prefix)
            for assignment in re.finditer(r'(?:\b(?:const|let|var)\s+)?\b([A-Za-z_$][\w$]*)\s*=\s*([^;\n]+)',prefix):
                if not list(sensitive_sources(assignment[2])):continue
                variable=assignment[1]
                if not re.search(r'\b'+re.escape(variable)+r'\b',args):continue
                if re.search(r'\b'+re.escape(variable)+r'\s*=',prefix[assignment.end():]):continue
                via=variable;source_offset=start+assignment.start();break
        if source_offset is None:continue
        # A fetch option that only enables a flag isn't an outgoing secret value. The expression must occur in call args.
        out.append({'line':code[:sink.start()].count('\n')+1,'source_line':code[:source_offset].count('\n')+1,'sink':sink[0].split('(')[0].strip(),'via':via,'excerpt':text[sink.start():end+1][:700], 'method':'direct network argument' if via is None else 'bounded local assignment to network argument'})
    return out
