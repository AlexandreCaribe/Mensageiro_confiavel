import socket
import hashlib
import base64
from cryptography.fernet import Fernet
import threading
import json
import pickle

mensagens = []

# Define a porta padrão para a comunicação UDP.
porta = 7773
'''
    Classe do Relógio lógico de Lamport que detém as funções de incremento do relógio, atualização e sua inicialização
'''
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

def gerar_chave_fernet(input_key):
    hash_key = hashlib.sha256(input_key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(hash_key)
    return fernet_key

def espera_por_mensagem(sock, relogio, nick, chave):
    while True:
        try:
            # Recebe dados do socket (1024 bytes)
            data, addr = sock.recvfrom(1024)

            # Carrega os dados recebidos usando pickle: mensagem criptografada e timestamp
            msg_codificada, tempo_recebido = pickle.loads(data)

            # Descriptografa a mensagem usando a função decodificar_mensagem e a chave
            msg_decodificada = decodificar_mensagem(chave, msg_codificada)

            # Converte a mensagem descriptografada de JSON para um dicionário Python
            message = json.loads(msg_decodificada)

            # Atualiza o relógio lógico com o timestamp recebido
            relogio.update(tempo_recebido)

            # Formata a mensagem para exibição
            formatted_message = f"\n{message['nick']}: {message['text']}"

            # Imprime a mensagem formatada no console
            #print("recebi")
            print(message['text'])

            if (message['text'] == "/historico"):
                max = len(mensagens)
                #print("Quantidade de mensagens", max)
                concat = ""
                for i in range(0, max):
                    concat = "".join(mensagens)
                print("env  iando: " + concat)
                envia_mensagem(sock,relogio,nick,chave,concat)
            else:
                print(formatted_message)
                mensagens.append(formatted_message)

        except Exception as e:
            # Captura exceções ao receber mensagens e imprime uma mensagem de erro
            print("\n")

def envia_mensagem(sock, relogio, nick, chave, concat):
    lamport_time = relogio.increment()
    message_data = json.dumps({"nick": nick, "text": concat})
    encrypted_data = codificar_mensagem(chave, message_data)
    data = pickle.dumps((encrypted_data, lamport_time))
    ip = f'127.0.0.1'
    portad = 7755
    endereco = (ip, portad)
    sock.sendto(data, endereco)


def codificar_mensagem(chave, message):
    fernet = Fernet(chave)
    return fernet.encrypt(message.encode())

def decodificar_mensagem(chave, encrypted_message):
    fernet = Fernet(chave)
    return fernet.decrypt(encrypted_message).decode()


def main():
    # Usuário se identifica no chat com um nick
    nick = input("Digite o seu nick: ")

    chave_inicial = '#Chavef8'
    chave = gerar_chave_fernet(chave_inicial)

    print("\n\n\n")

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # Associa o socket a um endereço e porta específicos; neste caso, o endereço é vazio ('') indicando
    # que ele pode receber mensagens em qualquer interface de rede e a porta é definida pelo valor da variável 'porta'
    sock.bind(('', porta))
    # Inicializa um relógio de Lamport para controle de ordem em mensagens concorrentes
    relogio = LamportClock()
    print(f"Servidor UDP iniciado e aguardando mensagens na porta {porta}...")

    listener_thread = threading.Thread(target=espera_por_mensagem, args=(sock, relogio, nick, chave), daemon=True)
    listener_thread.start()


    while True:
        pass  # Loop infinito para manter o programa em execução
if __name__ == "__main__":
    main()