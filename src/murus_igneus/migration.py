"""Independent configuration translator. SPDX-License-Identifier: MIT."""
from dataclasses import dataclass, field
import ipaddress as ip
import json
import re
import shlex

VERSION='0.3.0-alpha.9'  # single runtime source; __init__.py must match (see tests/test_hardening.py)

class Error(ValueError): pass

@dataclass
class Node:
    kind: str
    name: str
    values: dict = field(default_factory=dict)
    children: list = field(default_factory=list)

def parse(text):
    if not isinstance(text, str) or len(text.encode()) > 8*1024**2:
        raise Error('Backup non valido o superiore a 8 MiB')
    root=Node('root',''); stack=[root]
    for number,line in enumerate(text.splitlines(),1):
        line=line.strip()
        if not line or line.startswith('#'): continue
        try: words=shlex.split(line,comments=False)
        except ValueError as e: raise Error(f'Riga {number}: stringa multilinea o non chiusa') from e
        if not words: continue
        cmd,args=words[0],words[1:]; current=stack[-1]
        if cmd in ('config','edit') and args:
            if (cmd=='config' and current.kind not in ('root','edit')) or (cmd=='edit' and current.kind!='config'):
                raise Error(f'Riga {number}: struttura non valida')
            node=Node(cmd,' '.join(args)); current.children.append(node);stack.append(node)
        elif cmd in ('end','next') and not args:
            if current.kind!=('edit' if cmd=='next' else 'config'): raise Error(f'Riga {number}: chiusura non valida')
            stack.pop()
        elif cmd=='set' and len(args)>=2: current.values[args[0]]=args[1:]
        elif cmd=='unset' and len(args)==1: current.values.pop(args[0],None)
        else: raise Error(f'Riga {number}: comando non supportato ({cmd})')
    if len(stack)!=1: raise Error('Backup incompleto')
    return root

def one(v,k,default=''):
    a=v.get(k,[default])
    if len(a)!=1: raise Error(f'Valore multiplo: {k}')
    return a[0]

def flag(v,k,default='disable'):
    x=one(v,k,default)
    if x not in ('enable','disable'): raise Error(f'Booleano non valido: {k}')
    return x=='enable'

def net(values):
    if len(values)!=2: raise Error('Subnet non valida')
    n=ip.ip_network('/'.join(values),strict=False)
    if n.version!=4: raise Error('IPv6 non supportato')
    return str(n)

def ports(values):
    for p in values:
        if not re.fullmatch(r'\d{1,5}(-\d{1,5})?',p): raise Error('Porte sorgente o sintassi avanzata non supportate')
        parts=list(map(int,p.split('-')))
        if not all(1<=x<=65535 for x in parts) or parts[0]>parts[-1]: raise Error('Porta non valida')
    return values

Q=json.dumps

def baseline(management='eth0'):
    return f'''add table inet murus_igneus
flush table inet murus_igneus
table inet murus_igneus {{
 chain input {{ type filter hook input priority 0; policy drop;
  iifname "lo" accept
  ct state invalid drop
  ct state established,related accept
  iifname {Q(management)} tcp dport 8443 accept
  iifname {Q(management)} udp sport 67 udp dport 68 accept
  iifname {Q(management)} ip protocol icmp accept
 }}
 chain forward {{ type filter hook forward priority 0; policy drop; }}
}}
'''

def translate(text,mapping,management='eth0'):
    root=parse(text); blocked=[];warnings=[];sections={}
    supported={'system interface','firewall address','firewall addrgrp','firewall service custom','firewall service group','firewall policy','router static'}
    meta={'system global','system settings','system dns','system ntp','system admin','system accprofile','system console','system central-management','system auto-install'}
    for s in root.children:
        if s.name in sections: blocked.append('Sezione duplicata: '+s.name)
        sections[s.name]=s
        if s.name not in supported|meta: blocked.append('Sezione non supportata: '+s.name)
        if s.name in meta:warnings.append('Impostazioni locali non importate: '+s.name)
    if not sections:blocked.append('Nessuna configurazione riconoscibile')
    settings=sections.get('system settings',Node('','')).values
    if flag(settings,'central-nat') or flag(settings,'asymroute') or one(settings,'ngfw-mode','profile-based')!='profile-based':
        blocked.append('Central NAT, routing asimmetrico e NGFW policy-based non supportati')
    if one(sections.get('system global',Node('','')).values,'vdom-mode','no-vdom')!='no-vdom':blocked.append('Multi-VDOM non supportato')
    def entries(name):
        result={}
        for n in sections.get(name,Node('','')).children:
            if n.name in result:blocked.append(f'Elemento duplicato in {name}: {n.name}')
            result[n.name]=n
        return result
    interfaces=entries('system interface');addresses=entries('firewall address');groups=entries('firewall addrgrp')
    services=entries('firewall service custom');sgroups=entries('firewall service group');policies=entries('firewall policy');routes=entries('router static')
    if not isinstance(mapping,dict) or not all(isinstance(k,str) and isinstance(v,str) for k,v in mapping.items()):raise Error('Associazioni non valide')
    if len(set(mapping.values()))!=len(mapping):blocked.append('Le porte devono essere associate a schede distinte')
    ops=[];subnets=[]
    for name,dev in mapping.items():
        try:
            if name not in interfaces or not re.fullmatch(r'[a-zA-Z0-9_.-]{1,15}',dev) or dev in (management,'lo'):raise Error('Scheda non valida o riservata')
            n=interfaces[name];v=n.values
            allowed={'vdom','ip','allowaccess','type','alias','role','snmp-index','status','description','mode','device-identification','lldp-reception','lldp-transmission','speed','estimated-upstream-bandwidth','estimated-downstream-bandwidth'}
            if n.children or set(v)-allowed:raise Error('Opzioni interfaccia non supportate: '+', '.join(sorted(set(v)-allowed)))
            if one(v,'type','physical')!='physical' or one(v,'mode','static')!='static' or one(v,'vdom','root')!='root' or one(v,'status','up')!='up':raise Error('Supportate solo porte fisiche attive con IPv4 statico nel VDOM root')
            ops.append({'kind':'link','interface':dev})
            val=v.get('ip',['0.0.0.0','0.0.0.0'])
            if len(val)!=2:raise Error('Indirizzo interfaccia non valido')
            if val[0]!='0.0.0.0':
                prefix=ip.ip_network('0.0.0.0/'+val[1]).prefixlen;a=ip.IPv4Interface(val[0]+'/'+str(prefix))
                if any(a.network.overlaps(old) for old in subnets):raise Error('Subnet sovrapposte sulle porte dati')
                subnets.append(a.network);ops.append({'kind':'address','interface':dev,'address':str(a)})
        except (Error,ValueError) as e:blocked.append(f'Interfaccia {name}: {e}')
    addr_memo={};svc_memo={}  # per-group results, deduplicated: nested groups stay linear instead of exponential
    def address(name,trail=()):
        if name=='all':return ['0.0.0.0/0']
        if name in trail:raise Error('Ciclo nei gruppi indirizzi')
        if name in groups:
            if name in addr_memo:return addr_memo[name]
            n=groups[name]
            if n.children or set(n.values)-{'member','uuid','comment','color'}:raise Error('Gruppo indirizzi avanzato')
            addr_memo[name]=list(dict.fromkeys(x for m in n.values.get('member',[]) for x in address(m,trail+(name,))))
            return addr_memo[name]
        if name not in addresses:raise Error('Indirizzo assente: '+name)
        n=addresses[name];v=n.values
        if n.children or set(v)-{'type','subnet','uuid','comment','color','associated-interface','allow-routing'} or one(v,'type','ipmask')!='ipmask':raise Error('Indirizzo avanzato non supportato: '+name)
        return [net(v.get('subnet',['0.0.0.0','0.0.0.0']))]
    def service(name,trail=()):
        builtin={'ALL':[('all',())],'HTTP':[('tcp',('80',))],'HTTPS':[('tcp',('443',))],'SSH':[('tcp',('22',))],'DNS':[('tcp',('53',)),('udp',('53',))],'PING':[('icmp',())],'ALL_TCP':[('tcp',())],'ALL_UDP':[('udp',())]}
        if name not in services and name in builtin:return builtin[name]
        if name in trail:raise Error('Ciclo nei gruppi servizi')
        if name in sgroups:
            if name in svc_memo:return svc_memo[name]
            n=sgroups[name]
            if n.children or set(n.values)-{'member','comment','color','uuid','proxy'} or flag(n.values,'proxy'):raise Error('Gruppo servizi avanzato')
            svc_memo[name]=list(dict.fromkeys(x for m in n.values.get('member',[]) for x in service(m,trail+(name,))))
            return svc_memo[name]
        if name not in services:raise Error('Servizio assente: '+name)
        n=services[name];v=n.values
        if n.children or set(v)-{'protocol','tcp-portrange','udp-portrange','comment','color','category'} or one(v,'protocol','TCP/UDP/SCTP') not in ('TCP/UDP/SCTP','TCP/UDP/UDP-Lite/SCTP'):raise Error('Servizio avanzato non supportato: '+name)
        result=[(proto,tuple(ports(v[key]))) for proto,key in [('tcp','tcp-portrange'),('udp','udp-portrange')] if v.get(key)]
        if not result:raise Error('Servizio senza porte supportate')
        return result
    def mapped(names):
        if not names or any(x not in mapping for x in names):raise Error('Associare tutte le interfacce usate')
        return '{ '+', '.join(Q(mapping[x]) for x in names)+' }'
    def nets(names):
        a=sorted(set(x for name in names for x in address(name)))
        if not a:raise Error('Indirizzi mancanti')
        return '{ '+', '.join(a)+' }'
    # Reuse only our input chain; all migrated policy traffic goes through forward.
    lines=baseline(management).split(' chain forward')[0].splitlines()+[' chain forward { type filter hook forward priority 0; policy drop;','  ct state invalid drop','  ct state established,related accept']
    nat=[];count=0
    for ident,n in policies.items():
        v=n.values
        if one(v,'status','enable')=='disable':warnings.append('Policy disabilitata omessa: '+ident);continue
        try:
            allowed={'name','uuid','srcintf','dstintf','srcaddr','dstaddr','action','schedule','service','nat','logtraffic','logtraffic-start','status','comments','utm-status','inspection-mode','ssl-ssh-profile'}
            if not ident.isdecimal() or n.children or set(v)-allowed:raise Error('ID, sottoconfigurazione o opzioni non supportati: '+', '.join(sorted(set(v)-allowed)))
            if flag(v,'utm-status') or one(v,'ssl-ssh-profile','no-inspection')!='no-inspection':raise Error('Controlli UTM o ispezione SSL non riproducibili')
            if one(v,'schedule')!='always':raise Error('Richiesta schedule esplicita always')
            action=one(v,'action','deny')
            if action not in ('accept','deny'):raise Error('Azione non supportata')
            match=f'iifname {mapped(v.get("srcintf",[]))} oifname {mapped(v.get("dstintf",[]))} ip saddr {nets(v.get("srcaddr",[]))} ip daddr {nets(v.get("dstaddr",[]))}'
            protocols=[x for s in v.get('service',[]) for x in service(s)]
            if not protocols:raise Error('Servizi mancanti')
            mark=count+1;snat=flag(v,'nat') and action=='accept'
            for proto,p in protocols:
                m=match
                if proto=='icmp':m+=' ip protocol icmp icmp type echo-request'
                elif proto in ('tcp','udp'):
                    m+=' ip protocol '+proto
                    if p:m+=f' {proto} dport {{ '+', '.join(p)+' }'
                if snat:m+=f' ct mark set {mark}'
                if one(v,'logtraffic','disable')!='disable':lines.append(f'  {m} limit rate 20/second log prefix "OW policy {ident} "')
                lines.append('  '+m+(' accept' if action=='accept' else ' drop')+f' comment "policy {ident}"')
            if snat:nat.append(f'  ct mark {mark} oifname {mapped(v["dstintf"])} masquerade')
            count+=1
        except (Error,ValueError,RecursionError) as e:blocked.append(f'Policy {ident}: {e}')
    lines+=[' }',' chain postrouting { type nat hook postrouting priority 100; policy accept;']+nat+[' }','}']
    for ident,n in routes.items():
        v=n.values
        if one(v,'status','enable')=='disable':continue
        try:
            if n.children or set(v)-{'dst','gateway','device','distance','priority','comment','status'}:raise Error('Opzioni rotta non supportate')
            dev=one(v,'device');mapped([dev]);distance=int(one(v,'distance','10'));priority=int(one(v,'priority','0'))
            if not 1<=distance<=255 or not 0<=priority<=65535:raise Error('Metrica non valida')
            ops.append({'kind':'route','destination':net(v.get('dst',['0.0.0.0','0.0.0.0'])),'gateway':str(ip.IPv4Address(one(v,'gateway'))),'interface':mapping[dev],'metric':distance*65536+priority})
        except (Error,ValueError) as e:blocked.append(f'Rotta {ident}: {e}')
    return {'version':VERSION,'ready':not blocked,'blockers':blocked,'warnings':warnings,'interfaces':list(interfaces),'mapping':mapping,'network_ops':ops,'nftables':'\n'.join(lines)+'\n','counts':{'interfaces':len(interfaces),'addresses':len(addresses),'groups':len(groups),'services':len(services),'policies':count,'routes':len(routes)}}


