# vim:sw=4 ts=4 et:
from fabric.api import *

PRODUCTION_HOSTS = [
    'infra-2-a.itl.rslon.torchbox.net',
    'infra-2-b.itl.rslon.torchbox.net',
]

env.roledefs = {
    'production': [ "root@{}".format(host) for host in PRODUCTION_HOSTS ]
}

@roles('production')
def deploy():
    with cd('/opt/httpkeys'):
        with settings(sudo_user='sshkeys'):
            sudo('git pull')
            sudo('/opt/httpkeys/.venv/bin/pip install -r requirements.txt')
    run('touch -h /etc/tbx/uwsgi/conf.d/httpkeys.ini')

