"""Native editable Murus Igneus configuration. SPDX-License-Identifier: MIT."""
import ipaddress as ip
import json
try:
    from .migration import translate, parse, one, flag, net, ports, Error, VERSION
except ImportError:  # run as a script from this directory (how the service starts)
    from migration import translate, parse, one, flag, net, ports, Error, VERSION

KINDS=('interfaces','addresses','groups','services','service_groups','policies','routes')
BUILTINS=('ALL','HTTP','HTTPS','SSH','DNS','PING','ALL_TCP','ALL_UDP')
def empty():return {'schema':1,**{k:[] for k in KINDS}}
def compile_config(config,management='eth0'):
    if not isinstance(config,dict) or config.get('schema')!=1 or set(config)-set(KINDS)-{'schema'}:raise Error('Formato configurazione Murus Igneus non valido')
    c=json.loads(json.dumps(config));parts=[];mapping={}
    def rows(kind,allowed,key='name'):
        result=c.get(kind,[])
        if not isinstance(result,list) or len(result)>1000:raise Error('Elenco non valido: '+kind)
        seen=set()
        for r in result:
            if not isinstance(r,dict) or set(r)-set(allowed.split()):raise Error('Campi non validi: '+kind)
            name=r.get(key)
            if not isinstance(name,str) or not name.strip() or len(name)>128 or any(ord(x)<32 for x in name):raise Error('Nome/ID non valido: '+kind)
            if name in seen:raise Error('Nome/ID duplicato: '+name)
            seen.add(name)
        c[kind]=result
        return result
    def val(x):
        if not isinstance(x,str) or any(ord(ch)<32 for ch in x):raise Error('Valore testuale non valido')
        return json.dumps(x,ensure_ascii=False)
    def add(section,entries):
        parts.append('config '+section)
        for name,fields in entries:
            parts.append('edit '+val(name))
            for k,v in fields.items():
                if isinstance(v,list):
                    if not v:raise Error('Selezione vuota: '+k)
                    parts.append('set '+k+' '+' '.join(val(x) for x in v))
                else:parts.append('set '+k+' '+val(v))
            parts.append('next')
        parts.append('end')
    def boolean(r,k,default=False):
        v=r.get(k,default)
        if type(v)!=bool:raise Error('Booleano non valido: '+k)
        return 'enable' if v else 'disable'
    def subnet(s):
        n=ip.IPv4Network(s,strict=False);return [str(n.network_address),str(n.netmask)]
    interfaces=[]
    for r in rows('interfaces','name device address'):
        if not isinstance(r.get('device'),str):raise Error('Scheda mancante')
        mapping[r['name']]=r['device']
        a=ip.IPv4Interface(r['address']) if r.get('address') else None
        interfaces.append((r['name'],{'type':'physical','mode':'static','ip':[str(a.ip),str(a.netmask)] if a else ['0.0.0.0','0.0.0.0']}))
    add('system interface',interfaces)
    addresses=[]
    for r in rows('addresses','name subnet'):
        if r['name']=='all':raise Error('all è un indirizzo riservato')
        addresses.append((r['name'],{'subnet':subnet(r['subnet'])}))
    add('firewall address',addresses)
    groups=rows('groups','name members')
    if any(r['name']=='all' or r['name'] in {a['name'] for a in c['addresses']} for r in groups):raise Error('Nome gruppo indirizzi riservato o duplicato')
    add('firewall addrgrp',[(r['name'],{'member':r['members']}) for r in groups])
    services=[]
    for r in rows('services','name tcp udp'):
        if any(not isinstance(r.get(k,''),str) for k in ('tcp','udp')):raise Error('Porte non valide')
        fields={k+'-portrange':r[k].split() for k in ('tcp','udp') if r.get(k)}
        if not fields:raise Error('Specificare almeno una porta TCP o UDP')
        services.append((r['name'],fields))
    add('firewall service custom',services)
    sgroups=rows('service_groups','name members')
    if any(r['name'] in set(BUILTINS)|{s['name'] for s in c['services']} for r in sgroups):raise Error('Nome gruppo servizi riservato o duplicato')
    add('firewall service group',[(r['name'],{'member':r['members']}) for r in sgroups])
    policies=[]
    for r in rows('policies','id name srcintf dstintf srcaddr dstaddr service action nat log enabled','id'):
        if not r['id'].isdecimal() or not 1<=int(r['id'])<=4294967295:raise Error('ID policy non valido')
        fields={k:r[k] for k in ('srcintf','dstintf','srcaddr','dstaddr','service','action')}
        fields.update({'name':r.get('name',''),'schedule':'always','nat':boolean(r,'nat'),'logtraffic':'all' if boolean(r,'log')=='enable' else 'disable','status':boolean(r,'enabled',True)})
        policies.append((r['id'],fields))
    add('firewall policy',policies)
    routes=[]
    for r in rows('routes','id destination gateway interface distance priority enabled','id'):
        if r['destination'] in ('0.0.0.0','default'):r['destination']='0.0.0.0/0'
        if r['interface']==management and r['interface'] not in mapping:raise Error(management+' è riservata alla gestione: scegliere una interfaccia dati configurata')
        fields={'dst':subnet(r['destination']),'gateway':str(ip.IPv4Address(r['gateway'])),'device':r['interface'],'distance':str(r.get('distance',10)),'priority':str(r.get('priority',0)),'status':boolean(r,'enabled',True)}
        routes.append((r['id'],fields))
    add('router static',routes)
    source='\n'.join(parts)+'\n';plan=translate(source,mapping,management)
    def validate_groups(items,known):
        graph={r['name']:r['members'] for r in items};done=set()
        def visit(name,trail):
            if name in trail:raise Error('Ciclo nei gruppi: '+name)
            if name in done:return
            if name not in graph:
                if name not in known:raise Error('Riferimento assente: '+name)
                return
            members=graph[name]
            if not isinstance(members,list) or not members or not all(isinstance(m,str) for m in members):raise Error('Membri del gruppo non validi: '+name)
            if len(trail)>64:raise Error('Gruppi troppo annidati')
            for m in members:visit(m,trail+(name,))
            done.add(name)
        for name in graph:visit(name,())
    validate_groups(c['groups'],{'all'}|{r['name'] for r in c['addresses']})
    validate_groups(c['service_groups'],set(BUILTINS)|{r['name'] for r in c['services']})
    for r in c['services']:
        ports(r.get('tcp','').split());ports(r.get('udp','').split())
    check=translate(source.replace('set status "disable"','set status "enable"'),mapping,management)
    plan['blockers']+=check['blockers']
    plan['blockers']=list(dict.fromkeys(plan['blockers']));plan['ready']=not plan['blockers']
    plan['version']=VERSION;plan['configuration']=c
    return plan

def from_backup(text,mapping,management='eth0'):
    original=translate(text,mapping,management)
    if not original['ready']:return original
    sections={s.name:s for s in parse(text).children};c=empty()
    def rows(s):return sections[s].children if s in sections else []
    for n in rows('system interface'):
        if n.name not in mapping:continue
        v=n.values;a=v.get('ip',['0.0.0.0','0.0.0.0']);address=str(ip.IPv4Interface(a[0]+'/'+str(ip.IPv4Network('0.0.0.0/'+a[1]).prefixlen))) if a[0]!='0.0.0.0' else ''
        c['interfaces'].append({'name':n.name,'device':mapping[n.name],'address':address})
    for n in rows('firewall address'):c['addresses'].append({'name':n.name,'subnet':net(n.values.get('subnet',['0.0.0.0','0.0.0.0']))})
    for dest,section in [('groups','firewall addrgrp'),('service_groups','firewall service group')]:
        for n in rows(section):c[dest].append({'name':n.name,'members':n.values.get('member',[])})
    for n in rows('firewall service custom'):c['services'].append({'name':n.name,'tcp':' '.join(n.values.get('tcp-portrange',[])),'udp':' '.join(n.values.get('udp-portrange',[]))})
    for n in rows('firewall policy'):
        v=n.values;c['policies'].append({'id':n.name,'name':one(v,'name'),**{k:v.get(k,[]) for k in ('srcintf','dstintf','srcaddr','dstaddr','service')},'action':one(v,'action','deny'),'nat':flag(v,'nat'),'log':one(v,'logtraffic','disable')!='disable','enabled':one(v,'status','enable')!='disable'})
    for n in rows('router static'):
        v=n.values;c['routes'].append({'id':n.name,'destination':net(v.get('dst',['0.0.0.0','0.0.0.0'])),'gateway':one(v,'gateway'),'interface':one(v,'device'),'distance':int(one(v,'distance','10')),'priority':int(one(v,'priority','0')),'enabled':one(v,'status','enable')!='disable'})
    for section,allowed in {'firewall address':{'type','subnet','uuid','comment','color','associated-interface','allow-routing'},'firewall service custom':{'protocol','tcp-portrange','udp-portrange','comment','color','category'}}.items():
        for n in rows(section):
            if n.children or set(n.values)-allowed or (section=='firewall address' and one(n.values,'type','ipmask')!='ipmask') or (section=='firewall service custom' and one(n.values,'protocol','TCP/UDP/SCTP') not in ('TCP/UDP/SCTP','TCP/UDP/UDP-Lite/SCTP')):raise Error('Oggetto non modificabile nel formato nativo: '+n.name)
    all_enabled=text.replace('set status disable','set status enable').replace('set status "disable"','set status "enable"')
    check=translate(all_enabled,mapping,management)
    if not check['ready']:raise Error('Elementi disabilitati non convertibili: '+'; '.join(check['blockers']))
    plan=compile_config(c,management)
    if plan['nftables']!=original['nftables'] or plan['network_ops']!=original['network_ops']:raise Error('Conversione editor non equivalente: importazione bloccata')
    plan['warnings']+=original['warnings'];return plan


_compile_base=compile_config
def compile_config(config,management='eth0'):
    import copy
    try:
        from . import security, networking, enterprise, parental
    except ImportError:
        import security, networking, enterprise, parental
    if not isinstance(config,dict):raise Error('Configurazione non valida')
    parent_settings=parental.validate(config,management)
    config={k:v for k,v in config.items() if k!='parental'}
    extensions=enterprise.validate(config,management)
    config={k:v for k,v in config.items() if k not in extensions}
    settings=security.validate(config,management)
    original=copy.deepcopy(config);prepared,interfaces,services,vlans=networking.prepare(original,management)
    base={k:v for k,v in prepared.items() if k not in ('vpn','utm')}
    for row in base.get('interfaces',[]):
        if row.get('name')=='VPN' or row.get('device')==security.WG:raise Error('VPN/mivpn0 sono riservati al tunnel')
    devices={r.get('device') for r in base.get('interfaces',[])}
    if settings['vpn']['enabled']:
        if settings['vpn']['public_device'] not in devices:raise Error('Associare la porta pubblica VPN tra le interfacce dati')
        tunnel=ip.IPv4Interface(settings['vpn']['address'])
        for r in base.get('interfaces',[]):
            if r.get('address') and ip.IPv4Interface(r['address']).network.overlaps(tunnel.network):raise Error('Subnet VPN sovrapposta alle reti locali')
            if r.get('address') and any(ip.IPv4Interface(r['address']).network.overlaps(ip.IPv4Network(n)) for p in settings['vpn']['peers'] for n in p['allowed_ips']):raise Error('Rete remota VPN sovrapposta alle reti locali')
        base.setdefault('interfaces',[]).append({'name':'VPN','device':security.WG,'address':''})
    if settings['utm']['proxy']:
        port=next((r for r in base.get('interfaces',[]) if r.get('device')==settings['utm']['proxy_device']),None)
        if not port or not port.get('address'):raise Error('Il proxy richiede una porta dati con IPv4 statico')
    if settings['vpn']['enabled']:
        devices_by_name={r['name']:r['device'] for r in interfaces}
        if any(r.get('enabled',True) and r['protocol']=='udp' and r['external_port']==settings['vpn']['port'] and devices_by_name[r['interface']]==settings['vpn']['public_device'] for r in services['port_forwards']):raise Error('La porta DNAT è riservata alla VPN WireGuard')
    plan=_compile_base(base,management)
    if settings['vpn']['enabled']:plan['configuration']['interfaces']=[r for r in plan['configuration']['interfaces'] if r['name']!='VPN']
    plan['configuration'].update(settings);plan['security']=settings
    plan['nftables']=security.decorate(plan['nftables'],settings)
    networking.decorate(plan,interfaces,services,vlans)
    plan['configuration'].update(extensions);plan['enterprise']=extensions
    plan['nftables']=enterprise.decorate(plan['nftables'],extensions,interfaces)
    parental.decorate(plan,parent_settings,interfaces)
    plan['version']=VERSION
    return plan



