from socket import create_connection
from ssl import SSLContext, PROTOCOL_TLS_CLIENT, TLSVersion
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import pkcs12
import tempfile
from tempfile import NamedTemporaryFile
import os
import sys
import argparse

def get_userdata(p12_fname):
    with open(p12_fname, "rb") as f:
        p12 = f.read()
    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password=None)
    return (private_key, user_cert, ca_cert)

def print_help():
    print("\nInstruções de uso do programa:\n")
    print("   -user <FNAME>                  Especifica o ficheiro com dados do utilizador (por omissão: userdata.p12)")
    print("   send <UID> <SUBJECT>           Envia uma mensagem com assunto <SUBJECT> para o utilizador com identificador <UID>")
    print("   askqueue                       Solicita ao servidor a lista de mensagens não lidas na fila do utilizador")
    print("   getmsg <NUM>                   Solicita ao servidor o envio da mensagem da fila com número <NUM>")
    print("   help                           Imprime estas instruções de uso")



# Criar o objeto ArgumentParser
parser = argparse.ArgumentParser(description='Aplicação Cliente')

parser.add_argument('-user', type=str, default='userdata.p12')

# Adicionar subparsers para os diferentes comandos
subparsers = parser.add_subparsers(dest='command')

# Subparser para o comando 'send'
send_parser = subparsers.add_parser('send')
send_parser.add_argument('uid', type=str)
send_parser.add_argument('subject', type=str)

# Subparser para o comando 'askqueue'
subparsers.add_parser('askqueue')

# Subparser para o comando 'getmsg'
getmsg_parser = subparsers.add_parser('getmsg')
getmsg_parser.add_argument('num', type=str)

# Subparser para o comando 'help'
subparsers.add_parser('help')

# Subparser para o comando 'exit'
subparsers.add_parser('exit')

# Analisar se os argumentos da linha de comando são válidos
try:
    sys.stderr = open(os.devnull, 'w')
    args = parser.parse_args()
    sys.stderr = sys.__stderr__
    
except:
    sys.stderr = sys.__stderr__
    sys.stderr.write('\nMSG SERVICE: command error!\n')
    print_help()
    sys.exit(1)
    
# Trata do comando help
if args.command == 'help':
    print_help()
    sys.exit(1)

#Prepara a string para o comando send
if args.command == 'send':
    message = input("Message: ")
    
    if len(message.encode('utf-8')) > 1000:
        sys.stderr.write('\nMSG SERVICE: Message should be less than 1000 bytes!')
        sys.exit(1)
        
    send = args.uid + '_flag%&_' + args.subject + '_flag%&_' + message 


# Extrair o conteudo do ficheiro do utilizador
private_key, user_cert, ca_cert = get_userdata(args.user)


# Salvar os dados do certificado e da chave em arquivos temporários
with NamedTemporaryFile(mode='w', delete=False) as cert_file, NamedTemporaryFile(mode='w', delete=False) as key_file:
    cert_file.write(user_cert.public_bytes(encoding=serialization.Encoding.PEM).decode())
    key_file.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                                             encryption_algorithm=serialization.NoEncryption()).decode())

# Definir a conexão
context = SSLContext(PROTOCOL_TLS_CLIENT)
context.verify_mode = ssl.CERT_REQUIRED
context.minimum_version = TLSVersion.TLSv1_3

context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name, password=None)
context.load_verify_locations(cadata=ca_cert.public_bytes(serialization.Encoding.PEM).decode())

os.unlink(cert_file.name)
os.unlink(key_file.name)

# Parâmetros do host
hostname='Message Service Server'
ip = '127.0.0.1'
port = 8444

try:
    with create_connection((ip, port)) as client:
        with context.wrap_socket(client, server_hostname=hostname) as tls:
            print(f'Conected using {tls.cipher()}\n')
            
            if args.command == 'exit':
                tls.sendall('exit'.encode())    
                data = tls.recv(1024).decode()
                print(data)
            
            if args.command == 'send':
                tls.sendall(send.encode())
                tls.sendall(user_cert.public_bytes(encoding=serialization.Encoding.PEM))
                data = tls.recv(1024).decode()
                print(f'Server: {data}')
                
            if args.command == 'askqueue':
                tls.sendall('askqueue'.encode())
                tls.sendall(user_cert.public_bytes(encoding=serialization.Encoding.PEM))
                data = tls.recv(2048).decode()
                print(data)
                
            if args.command == 'getmsg':
                tls.sendall(('getmsg' + '_flag%&_' + args.num).encode())
                tls.sendall(user_cert.public_bytes(encoding=serialization.Encoding.PEM))
                data = tls.recv(2048).decode()
                ##TODO -- fazer verificações da assinatura
                print(data)
except:
    sys.stderr.write("MSG SERVICE: Connection error!")
