# mensageiro.py
import sys
import socket
import hashlib
import base64
from cryptography.fernet import Fernet
import threading
import json
import pickle

maximo = 255

class LamportClock:
    """
    Implementação de um relógio de Lamport para estabelecer uma ordem de eventos
    em um sistema distribuído, crucial para a consistência de estado entre diferentes nós.
    """
    def __init__(self):
        # Valor inicial do relógio.
        self.value = 0
        # Lock para sincronização em ambientes multithread.
        self.lock = threading.Lock()

    def increment(self):
        """
        Incrementa o valor do relógio. Isso é feito antes de um nó enviar uma mensagem
        para assegurar a ordem das mensagens.
        """
        with self.lock:
            self.value += 1
            return self.value

    def update(self, received_time):
        """
        Atualiza o relógio com o maior valor entre o atual e o recebido, e incrementa em 1.
        Isso ajuda a manter a consistência da ordem dos eventos entre diferentes nós.
        """
        with self.lock:
            self.value = max(self.value, received_time) + 1
            return self.value


# Função para enviar mensagem
def enviar_mensagem(nome_usuario, conteudo_mensagem, chave, relogio):
    try:
        # Cria um socket UDP
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        porta = 7773

        # Obtém o endereço IP local do gateway
        ip_gateway = get_gateway_ip()

        if ip_gateway:
            # Cria um dicionário com os dados da mensagem
            mensagem = {
                "nick": nome_usuario,
                "text": conteudo_mensagem,
                "ip": ip_gateway
            }

            # Converte o dicionário para JSON
            mensagem_json = json.dumps(mensagem)

            # Codifica a mensagem usando uma função de codificação com uma chave
            mensagem_codificada = codificar_mensagem(chave, mensagem_json)

            # Obtém um novo timestamp incremental no relógio de Lamport
            tempo = relogio.increment()

            # Serializa os dados (mensagem criptografada e timestamp) usando o módulo pickle
            dados_serializados = pickle.dumps((mensagem_codificada, tempo))

            # Envia os dados serializados para o endereço IP do gateway
            #sock.sendto(dados_serializados, (ip_gateway, porta))
            """for i in range(1, 255):
                ip = f'172.16.103.{i}'
                endereco = (ip, porta)
                sock.sendto(dados_serializados, endereco)"""
            for i in range(0, maximo):
                ip_atual = f'172.16.103.{i}'
                ip_proximo = f'172.16.103.{(i % maximo) + 1}'  # Próximo IP no anel
                if ip_proximo == '172.16.103.1':
                    ip_proximo = f'172.16.103.1'
                '''
                if i == maximo - 1:
                    ip_proximo = f'172.16.103.{(i % maximo)}'  # Último IP no anel
                '''
                #print(ip_proximo)
                endereco_atual = (ip_atual, porta)
                endereco_proximo = (ip_proximo, porta)
                sock.sendto(dados_serializados, endereco_proximo)

            # Envia os dados para o próximo nó no anel
            if enviar_com_confirmacao(sock, dados_serializados, endereco_proximo):
                print("teste")
                #print(f'Dados enviados para {ip_proximo}')
            else:
                print(f'Enviado até {ip_proximo}')


            #print("Mensagem enviada com sucesso. ", ip_gateway)
            print("Mensagem enviada com sucesso. ")
        else:
            print("Não foi possível determinar o endereço IP do gateway.")
    except Exception as e:
        print(f"Ocorreu um erro ao enviar a mensagem: {e}")







# Função para enviar dados e aguardar confirmação
def enviar_com_confirmacao(sock, dados, endereco):
    tentativas = 0
    while tentativas < 3:
        sock.sendto(dados, endereco)
        sock.settimeout(1)  # Tempo limite de espera por uma resposta
        try:
            resposta, _ = sock.recvfrom(1024)
            if resposta == b'ACK':
                return True
        except socket.timeout:
            tentativas += 1
    return False








# Função para obter o endereço IP do gateway
def get_gateway_ip():
    try:
        # Conectar-se a um servidor externo para determinar o endereço do gateway, usando o Google DNS como exemplo
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Conecta ao Google DNS na porta 80
        s.connect(("8.8.8.8", 80))
        # Obtém o endereço IP local do socket
        gateway_ip = s.getsockname()[0]
        # Fecha o socket
        s.close()
        return gateway_ip
    except socket.error:
        return None

# Função para criar uma chave Fernet
def gerar_chave_fernet(chave):
    hash_chave = hashlib.sha256(chave.encode()).digest()
    chave_fernet = base64.urlsafe_b64encode(hash_chave)
    return chave_fernet

# Função para criptografar uma mensagem
def codificar_mensagem(chave, mensagem):
    fernet = Fernet(chave)
    return fernet.encrypt(mensagem.encode())
# Função principal
def main():
    # Verifica o número de argumentos
    if len(sys.argv) != 3:
        print("Uso: python3 mensageiro.py <nome_usuario> <conteudo_mensagem>")
        sys.exit(1)

    nome_usuario = sys.argv[1]
    conteudo_mensagem = sys.argv[2]

    # Cria uma chave para criptografia
    chave = gerar_chave_fernet('#Chavef8')

    # Inicializa um relógio de Lamport
    relogio = LamportClock()

    # Chama a função para enviar a mensagem
    enviar_mensagem(nome_usuario, conteudo_mensagem, chave, relogio)

if __name__ == "__main__":
    main()