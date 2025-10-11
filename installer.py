import os
divider = "=" * 50
print(divider)
print('oRoute Installer')
print(divider)

print('This script will install the oRoute daemon and client on your system.')
client_path = '/usr/local/bin/oRoute'
daemon_path = '/usr/local/bin/oRoute_daemon'

print(divider)
print('Files will be written to:')
print(f'Client: {client_path}')
print(f'Daemon: {daemon_path}')
print(divider)

confirm = input('Do you want to proceed? (y/n): ')
if confirm.lower() != 'y':
    print('Installation cancelled.')
    exit(0)

fp = os.path.join(os.path.dirname(__file__), 'oRoute.py')
fpd = os.path.join(os.path.dirname(__file__), 'oRoute_daemon.py')
if not os.path.isfile(fp) or not os.path.isfile(fpd):
    print('Error: oRoute.py or oRoute_daemon.py not found in the current directory.')
    exit(1)

print('Copying files...')
os.system('sudo cp {} {}'.format(fp, client_path))
os.system('sudo cp {} {}'.format(fpd, daemon_path))

print('Setting executable permissions...')
os.system('sudo chmod +x {}'.format(client_path))
os.system('sudo chmod +x {}'.format(daemon_path))

print('Installation complete.')

print('Cleaning up...')
print('Deleting installer scripts...')
root_dir = os.path.dirname(__file__)
remove_confirm = input('Do you want to delete {} (y/n)? '.format(root_dir))
if remove_confirm.lower() == 'y':
    os.system('sudo rm -rf {}'.format(root_dir))
    print('Installer scripts deleted.')


if __name__ == '__main__':
    pass