"""Explicitly confirmed live-to-disk installer. SPDX-License-Identifier: MIT."""
import argparse,fcntl,json,os,re,secrets,subprocess,sys,tempfile,time
from pathlib import Path
try:
    from .migration import Error
except ImportError:
    from migration import Error
try:
    from . import jobs
except ImportError:
    import jobs
PREVIEW=None
INSTALL_LOCK=Path('/run/murus-igneus-installer.lock')

def preserve_root_password(target, source=Path('/etc/shadow')):
    """Copy only the current root shadow record, never a factory password."""
    destination = Path(target)/'etc/shadow'
    if destination.is_symlink():raise Error('Shadow di destinazione non valido')
    root = [line for line in Path(source).read_text().splitlines() if line.startswith('root:')]
    if len(root)!=1 or len(root[0].split(':'))!=9:raise Error('Password console non disponibile')
    lines = destination.read_text().splitlines()
    if sum(line.startswith('root:') for line in lines)!=1:raise Error('Account root di destinazione non valido')
    info = destination.stat();temporary = destination.with_name('.shadow.murus')
    try:
        fd=os.open(temporary,os.O_CREAT|os.O_EXCL|os.O_WRONLY,0o600)
        with os.fdopen(fd,'w') as stream:stream.write('\n'.join(root[0] if line.startswith('root:') else line for line in lines)+'\n')
        os.chown(temporary,info.st_uid,info.st_gid);temporary.chmod(info.st_mode&0o777);temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)


def command(args):return subprocess.check_output(args,text=True,timeout=20)
def live():return Path('/etc/murus_igneus/live-image').exists() and Path('/run/live/medium/live/filesystem.squashfs').is_file()
def inventory():
    if not live():return {'live':False,'disks':[],'message':'Installer disponibile solo avviando la ISO Murus Igneus'}
    values=json.loads(command(['lsblk','--json','--bytes','--output','NAME,PATH,SIZE,TYPE,MODEL,MOUNTPOINTS,RO,MAJ:MIN']))['blockdevices']
    def mounted(d):return bool(any(d.get('mountpoints') or [])) or any(mounted(c) for c in d.get('children',[]))
    disks=[]
    for d in values:
        if d['type']!='disk' or d.get('ro') or mounted(d) or not re.fullmatch(r'/dev/(sd[a-z]+|vd[a-z]+|nvme[0-9]+n[0-9]+)',d['path']):continue
        if int(d['size'])<8*1024**3:continue
        seq=Path('/sys/class/block/'+d['name']+'/diskseq')
        identity=d['maj:min']+':'+(seq.read_text().strip() if seq.exists() else 'unknown')
        disks.append({'path':d['path'],'bytes':int(d['size']),'model':(d.get('model') or '').strip(),'identity':identity})
    return {'live':True,'disks':disks,'message':'Il disco selezionato verrà cancellato interamente. Minimo 8 GiB.' if disks else 'Nessun disco installabile: collega un disco non montato di almeno 8 GiB; nella VM aggiungi un disco virtuale.'}

def preview(path):
    global PREVIEW
    disk=next((d for d in inventory()['disks'] if d['path']==path),None)
    if not disk:raise Error('Disco assente, montato, riservato o troppo piccolo')
    PREVIEW={'id':secrets.token_hex(24),'disk':disk,'expires':time.time()+120}
    return {**PREVIEW,'confirmation':'CANCELLA '+disk['path']}

def start(data):
    global PREVIEW
    p=PREVIEW
    if not p or data.get('id')!=p['id'] or time.time()>p['expires'] or data.get('confirmation')!='CANCELLA '+p['disk']['path']:raise Error('Conferma esplicita scaduta o non valida')
    current=next((d for d in inventory()['disks'] if d['path']==p['disk']['path']),None)
    if current!=p['disk']:raise Error('Il disco è cambiato dopo la verifica')
    PREVIEW=None
    return jobs.start('Installazione su '+current['path'],lambda log:install(current,log))

def install(disk,log):
    # Serialize console and web installers across processes, before any disk write.
    fd=os.open(INSTALL_LOCK,os.O_CREAT|os.O_RDWR|os.O_NOFOLLOW,0o600)
    try:
        try:fcntl.flock(fd,fcntl.LOCK_EX|fcntl.LOCK_NB)
        except BlockingIOError:raise Error('Un’altra installazione è già in corso') from None
        _install(disk,log)
    finally:os.close(fd)


def _install(disk,log):
    # Revalidate immediately before the first destructive write.
    if disk not in inventory()['disks']:raise Error('Disco non più disponibile')
    path=disk['path'];part=lambda n:path+('p' if path[-1].isdigit() else '')+str(n)
    mounts=[];work=Path(tempfile.mkdtemp(prefix='murus-install-',dir='/run'));target=work/'target';source=work/'source';target.mkdir();source.mkdir()
    def run(args,data=None):jobs.run(args,log,data)
    def mount(args,where):run(['mount']+args+[str(where)]);mounts.append(str(where))
    try:
        log.write('Partizionamento GPT: BIOS boot, EFI, root ext4.\n');log.flush()
        run(['wipefs','--all',path])
        run(['sfdisk','--wipe','always',path], 'label: gpt\n,2M,21686148-6449-6E6F-744E-656564454649\n,256M,U\n,,L\n')
        run(['partprobe',path]);time.sleep(1)
        run(['mkfs.vfat','-F','32',part(2)]);run(['mkfs.ext4','-F','-L','MURUS_ROOT',part(3)])
        mount(['-o','loop,ro','/run/live/medium/live/filesystem.squashfs'],source)
        mount([part(3)],target)
        run(['rsync','-aHAX','--numeric-ids',str(source)+'/',str(target)+'/'])
        for name in ('/etc/murus_igneus','/var/lib/clamav','/var/lib/suricata','/var/lib/murus_igneus','/var/lib/murus-igneus'):
            if Path(name).exists():
                dest=target/name.lstrip('/');dest.mkdir(parents=True,exist_ok=True)
                run(['rsync','-aHAX','--numeric-ids',name+'/',str(dest)+'/'])
        run(['rsync','-a','/etc/default/murus-igneus',str(target/'etc/default/murus-igneus')])
        preserve_root_password(target)
        (target/'etc/murus_igneus/live-image').unlink(missing_ok=True)
        (target/'boot/efi').mkdir(parents=True,exist_ok=True);mount([part(2)],target/'boot/efi')
        uuid=command(['blkid','-s','UUID','-o','value',part(3)]).strip();efi=command(['blkid','-s','UUID','-o','value',part(2)]).strip()
        (target/'etc/fstab').write_text(f'UUID={uuid} / ext4 defaults 0 1\nUUID={efi} /boot/efi vfat umask=0077 0 2\n')
        for name in ('dev','proc','sys'):
            (target/name).mkdir(exist_ok=True);mount(['--rbind','/'+name],target/name);run(['mount','--make-rslave',str(target/name)])
        (target/'etc/default/grub').write_text('GRUB_TIMEOUT=2\nGRUB_DISTRIBUTOR="Murus Igneus"\nGRUB_TERMINAL="console serial"\nGRUB_SERIAL_COMMAND="serial --unit=0 --speed=115200"\nGRUB_CMDLINE_LINUX="net.ifnames=0 console=tty0 console=ttyS0,115200"\n')
        run(['chroot',str(target),'update-initramfs','-u','-k','all'])
        run(['chroot',str(target),'grub-install','--target=i386-pc','--recheck',path])
        run(['chroot',str(target),'grub-install','--target=x86_64-efi','--efi-directory=/boot/efi','--bootloader-id=Murus','--removable','--no-nvram'])
        run(['chroot',str(target),'update-grub']);run(['sync'])
        log.write('\nINSTALLAZIONE COMPLETATA. Spegni la VM, rimuovi la ISO e avvia dal disco.\n')
    finally:
        for where in reversed(mounts):
            subprocess.run(['umount','-R',where],stdout=log,stderr=subprocess.STDOUT,timeout=30)




def console_main(argv=None, read=None, log=None):
    parser=argparse.ArgumentParser(description='Installa Murus Igneus dalla live su un disco vuoto selezionato. Il disco viene cancellato solo dopo conferma esplicita.')
    parser.add_argument('--list',action='store_true',help='Mostra i dischi installabili senza modificarli')
    parser.add_argument('--disk',help='Disco da proporre; richiede sempre conferma interattiva')
    args=parser.parse_args(argv);out=log or sys.stdout;read=read or input
    if os.geteuid()!=0:
        print('Eseguire dalla console come root.',file=out);return 1
    data=inventory();print(data['message'],file=out)
    for index,disk in enumerate(data['disks'],1):
        print(f"{index}. {disk['path']} · {disk['bytes']/1024**3:.1f} GiB · {disk['model']}",file=out)
    if args.list:return 0 if data['live'] else 1
    if not data['live'] or not data['disks']:return 1
    if not sys.stdin.isatty():
        print('Installazione consentita solo da console interattiva; nessuna opzione di conferma automatica.',file=out);return 1
    try:
        choice=args.disk or read('Numero del disco (Invio per annullare): ').strip()
        if not choice:return 2
        disk=next((d for i,d in enumerate(data['disks'],1) if choice in (str(i),d['path'])),None)
        if disk is None:raise Error('Disco non presente tra le destinazioni installabili')
        confirmation='CANCELLA '+disk['path']
        print('TUTTI I DATI SU '+disk['path']+' SARANNO CANCELLATI. Per proseguire scrivi esattamente: '+confirmation,file=out,flush=True)
        if read('Conferma (Invio per annullare): ').strip()!=confirmation:
            print('Installazione annullata. Nessun disco modificato.',file=out);return 2
        install(disk,out)
        return 0
    except (EOFError,KeyboardInterrupt):
        print('Installazione annullata.',file=out);return 2
    except Exception as exc:
        print('ERRORE: '+str(exc),file=out);return 1
