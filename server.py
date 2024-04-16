from socket import socket, AF_INET, SOCK_STREAM
from ssl import SSLContext, PROTOCOL_TLS_SERVER, TLSVersion
import ssl
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography import x509
from tempfile import NamedTemporaryFile
import os
import json
from datetime import datetime
import signal

def getID(cert_pem):
    
    certificado = x509.load_pem_x509_certificate(cert_pem, default_backend())
    id = certificado.subject.get_attributes_for_oid(x509.OID_PSEUDONYM)[0]
    
    return id.value

def salvar_mensagem(parts, client_cert):
    
    certificado = x509.load_pem_x509_certificate(client_cert, default_backend())
    cn = certificado.subject.get_attributes_for_oid(x509.OID_PSEUDONYM)[0]
    #cn = certificado.subject.get_attributes_for_oid(x509.OID_COMMON_NAME)[0]
    
    # Verifica se a pasta "parts[0]" existe, senão, cria
    if not os.path.exists(parts[0]):
        os.makedirs(parts[0])

    # Lista os arquivos na pasta "parts[0]"
    arquivos = os.listdir(parts[0])

    # Calcula o próximo número de ordem para o novo arquivo
    num_ordem = len(arquivos) + 1

    # Cria um dicionário com os dados da mensagem
    mensagem = {
        ##TODO -- adicionar um 'para'
        ##########adicionar assinatura de quem mandou (message+destino+sender)
        "lida": 0,
        "subject": parts[1],
        "message": parts[2],
        "sender": cn.value,
        "time": str(datetime.now()),
        "cert": str(client_cert)
    }

    # Caminho do novo arquivo JSON
    nome_arquivo = os.path.join(parts[0], str(num_ordem) + '.json')

    # Salva os dados no arquivo JSON
    with open(nome_arquivo, 'w') as arquivo:
        json.dump(mensagem, arquivo)
        
def getmsg(pasta, nome_arquivo):
    caminho_arquivo = os.path.join(pasta, nome_arquivo + '.json')
    
    # Verifica se o arquivo existe
    if not os.path.isfile(caminho_arquivo):
        return None
    
    with open(caminho_arquivo, 'r') as arquivo:
        dados = json.load(arquivo)

        dados['lida'] = 1
            
        with open(caminho_arquivo, 'w') as arquivo:
            json.dump(dados, arquivo)
            
        return [valor for chave, valor in dados.items()]

        
# Extrai os certificados e a chave publica do ficheiro do utilizador
def get_userdata(p12_fname):
    with open(p12_fname, "rb") as f:
        p12 = f.read()
    (private_key, user_cert, [ca_cert]) = pkcs12.load_key_and_certificates(p12, password=None)
    return (private_key, user_cert, ca_cert)

def askqueue2(diretorio):
    mensagens_nao_lidas = []
    for arquivo in os.listdir(diretorio):
        if arquivo.endswith('.json'):
            with open(os.path.join(diretorio, arquivo), 'r') as f:
                mensagem = json.load(f)
                if mensagem.get('lida') == 0:
                    mensagens_nao_lidas.append(mensagem)
    return mensagens_nao_lidas

def askqueue(diretorio):
    if not os.path.exists(diretorio) or not os.listdir(diretorio):
        return 'MSG SERVICE: you have no messages!'
    
    mensagens_formatadas = []
    for arquivo in os.listdir(diretorio):
        if arquivo.endswith('.json'):
            with open(os.path.join(diretorio, arquivo), 'r') as f:
                mensagem = json.load(f)
                if mensagem.get('lida') == 0:
                    nome_arquivo = os.path.splitext(arquivo)[0]  # Remover a extensão .json
                    sender = mensagem.get('sender')
                    time = mensagem.get('time')
                    subject = mensagem.get('subject')
                    mensagem_formatada = f"{nome_arquivo}:{sender}:{time}:{subject}"
                    mensagens_formatadas.append(mensagem_formatada)
    
    if not mensagens_formatadas:
        return 'MSG SERVICE: you have no messages!'
    
    return '\n'.join(mensagens_formatadas)




# Obtem os certificados
private_key, server_cert, ca_cert = get_userdata('SERVER.p12')

# Salvar os dados do certificado e da chave em arquivos temporários
with NamedTemporaryFile(mode='w', delete=False) as cert_file, NamedTemporaryFile(mode='w', delete=False) as key_file:
    cert_file.write(server_cert.public_bytes(encoding=serialization.Encoding.PEM).decode())
    key_file.write(private_key.private_bytes(encoding=serialization.Encoding.PEM,
                                             format=serialization.PrivateFormat.TraditionalOpenSSL,
                                             encryption_algorithm=serialization.NoEncryption()).decode())

context = SSLContext(PROTOCOL_TLS_SERVER)
context.verify_mode = ssl.CERT_REQUIRED
context.minimum_version = TLSVersion.TLSv1_3

context.load_cert_chain(certfile=cert_file.name, keyfile=key_file.name, password=None)
context.load_verify_locations(cadata=ca_cert.public_bytes(serialization.Encoding.PEM).decode())

os.unlink(cert_file.name)
os.unlink(key_file.name)

ip = '127.0.0.1'
port = 8444

while True: 
    with socket(AF_INET, SOCK_STREAM) as server:
        server.bind((ip, port))
        server.listen(1)
        with context.wrap_socket(server, server_side=True) as tls:
            print('Server waiting connections')
            connection, address = tls.accept()
            
            #print(f'Conected using {connection.cipher()}\n')
            #print(f'By {address}\n')

            #receber mensagem
            data = connection.recv(2048).decode()
            parts = data.split("_flag%&_")
            print(f'Client: {data}')
            
            if len(parts) == 3:
                cert_pem = connection.recv(3000)
                salvar_mensagem(parts, cert_pem)
                connection.sendall('Message sended successfully'.encode())
                
            if data == 'askqueue':
                cert_pem = connection.recv(3000)
                id = getID(cert_pem)
                msgs = askqueue(id)
                connection.sendall(msgs.encode())
                
            if parts[0] == 'getmsg':
                cert_pem = connection.recv(3000)
                id = getID(cert_pem)
                msg = getmsg(id,parts[1])
                connection.sendall(msg[2].encode())

            if data == 'exit':
                connection.sendall('Servidor encerrado'.encode())
                break