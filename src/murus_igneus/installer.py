"""Explicitly confirmed live-to-disk installer. SPDX-License-Identifier: MIT."""
import hashlib,json,os,re,secrets,stat,subprocess,tempfile,time
from pathlib import Path
from migration import Error
import jobs
PREVIEW=None

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
    return {'live':True,'disks':disks,'message':'Il disco selezionato verrà cancellato interamente. Minimo 8 GiB.'}

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
        for name in ('/etc/murus_igneus','/var/lib/clamav','/var/lib/suricata','/var/lib/murus_igneus'):
            if Path(name).exists():
                dest=target/name.lstrip('/');dest.mkdir(parents=True,exist_ok=True)
                run(['rsync','-aHAX','--numeric-ids',name+'/',str(dest)+'/'])
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
