import socket
import hashlib
import base64
from cryptography.fernet import Fernet
import threading
import json
import pickle

# Lista para guardar as mensagens do histórico de mensagens
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







def envio_automatizado(nome_usuario, conteudo_mensagem, relogio, chave):
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
            sock.sendto(dados_serializados, (ip_gateway, porta))
            print("Mensagem enviada com sucesso.")
        else:
            print("Não foi possível determinar o endereço IP do gateway.")
    except Exception as e:
        print(f"Ocorreu um erro ao enviar a mensagem: {e}")














"""
    Função retorna o Gateway/IP do dispositivo do usuário
    Usado como forma de controle
"""
def get_gateway_ip():
    try:
        # Conectar-se a um servidor externo para determinar o endereço do gateway, usando o Google DNS como exemplo
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Conecta ao Google DNS na porta 80
        s.connect(("8.8.8.8", 80))
        # Obtém o endereço IP local do socket
        gateway_ip = s.getsockname()[0]
        #Fecha o socket
        s.close()
        return gateway_ip
    except socket.error:
        return None

"""
    Escuta a comunicação, até que chegue uma mensagem, a partir daí a mensagem é:
    - Descriptografada
    - Exibida para o usuário
"""
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
            formatted_message = f"\n{message['nick']} falou: {message['text']}"

            # Verifica se a mensagem é 'hist'; se sim, envia o histórico
            if message['text'] == 'hist':
                envia_mensagens_hist(sock, relogio, nick, chave)

            # Imprime a mensagem formatada no console
            print(formatted_message)

            # Adiciona a mensagem formatada e o endereço IP à lista de mensagens
            mensagens.append(formatted_message)
            mensagens.append(message['ip'])
        except Exception as e:
            # Captura exceções ao receber mensagens e imprime uma mensagem de erro
            print("\n")

"""
    É chamado por envia_mensagens_hist()
    Exibe o tamanho da lista de mensagens do Historico para identificar qual dos usuarios é mais antigo
"""
def espera_por_mensagem_hist(sock, relogio, nick, chave):
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
        formatted_message = f"{message['tamanho']}"
        # Exibe a mensagem.
        print("Tamanho da lista enviada na comunicação do user mais antigo",formatted_message)
        print("Tamanho da lista desse user",len(mensagens))
        # Verifica se o tamanho da lista recebida é igual ao tamanho da lista local
        if(int(formatted_message) == len(mensagens)):
            # Se forem iguais, envia o histórico
            envia_historico(sock, relogio, nick, chave)
    except Exception as e:
        print(f"\n")

"""
    Fica aguardando a chegada do envio das mensagens do Histórico até que chegue a lista das mensagens concatenadas
"""
def espera_hist(sock, relogio, nick, chave):
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
        formatted_message = f"\n{message['mensagens']}"

        # Exibe a mensagem.
        print("Histórico do chat",formatted_message)
    except Exception as e:
        print(f"\n\n")

"""
    Envia a lista de mensagens do Historico concatenando as mensagens para serem enviadas a todo varredura dos IPs
"""
def envia_historico(sock, relogio, nick, chave):
    # Inicializa uma string vazia para armazenar as mensagens concatenadas
    mensagem_concatenada = ''

    # Loop para percorrer a lista
    for item in mensagens:
        # Verifica se o item é uma string e, em seguida, concatena na mensagem
        if isinstance(item, str):
            mensagem_concatenada += item
            mensagem_concatenada += ' '
    # Imprime a mensagem concatenada
    print("Mensagem do historico: ",mensagem_concatenada)

    # Incrementa o relógio lógico com o timestamp recebido
    lamport_time = relogio.increment()

    # Converte o histórico de mensagens concatenado para formato JSON
    message_data = json.dumps({"Historico": mensagem_concatenada})

    # Codifica a mensagem usando uma função de codificação com uma chave
    encrypted_data = codificar_mensagem(chave, message_data)

    # Serializa os dados (mensagem criptografada e timestamp) usando o módulo pickle
    data = pickle.dumps((encrypted_data, lamport_time))

    '''
    Coloca todos os IPs da rede conectados no grupo
    '''

    for i in range(1, 255):
        ip = f'172.16.103.{i}'
        endereco = (ip, porta)
        sock.sendto(data, endereco)
    espera_hist(sock, relogio, nick, chave)

"""
    É chamada dentro da Thread de escuta de mensagens, se a mensagem for hist ela chama o envio do historico
    Onde é enviado o tamanho da lista de mensagens para que se saiba o user mais antigo
"""
def envia_mensagens_hist(sock, relogio, nick, chave):
    # Obtém um novo timestamp incremental no relógio de Lamport
    lamport_time = relogio.increment()

    # Converte informações sobre as mensagens para formato JSON
    message_data = json.dumps({"tamanho": len(mensagens)})

    # Codifica a mensagem usando uma função de codificação com uma chave
    encrypted_data = codificar_mensagem(chave, message_data)

    # Serializa os dados (mensagem criptografada e timestamp) usando o módulo pickle
    data = pickle.dumps((encrypted_data, lamport_time))

    '''
    Coloca todos os IPs da rede conectados no grupo para receber a mensagem.
    Loop de iteração sobre possíveis IPs na faixa de 172.16.103.1 a 172.16.103.254.
    '''
    for i in range(1, 255):
        ip = f'172.16.103.{i}'
        endereco = (ip, porta)

        # Envia os dados serializados para o endereço específico usando o socket
        sock.sendto(data, endereco)

    # Espera por duas mensagens históricas usando uma função específica
    espera_por_mensagem_hist(sock, relogio, nick, chave)
    espera_por_mensagem_hist(sock, relogio, nick, chave)


"""
    Função principal de envio de mensagens dos usuários no chat
    Ele digita a mensagem e ela é enviada passando o Nick do usuário, o conteúdo da mensagem e o IP dele
"""
def envia_mensagem(sock, relogio, nick, chave):
    while True:
        message_text = input("\n")
        lamport_time = relogio.increment()
        # Cria um dicionário com os dados da mensagem, incluindo nome de usuário (nick), texto da mensagem (text),
        # e o endereço IP do gateway obtido através da função get_gateway_ip()
        message_data = json.dumps({"nick": nick, "text": message_text, "ip": get_gateway_ip()})
        encrypted_data = codificar_mensagem(chave, message_data)
        data = pickle.dumps((encrypted_data, lamport_time))

        '''
        Coloca todos os IPs da rede conectados no grupo para receber a mensagem
        '''
        for i in range(1, 255):
            ip = f'172.16.103.{i}'
            endereco = (ip, porta)
            sock.sendto(data, endereco)

"""
    Gera uma chave Fernet com base na chave de entrada:
    - Converte a chave de entrada para um hash SHA-256
    - Codifica o hash usando base64
    Retorna a chave Fernet resultante.
"""
def gerar_chave_fernet(input_key):
    hash_key = hashlib.sha256(input_key.encode()).digest()
    fernet_key = base64.urlsafe_b64encode(hash_key)
    return fernet_key

"""
    Criptografa a mensagem fornecida usando a chave Fernet fornecida:
    - Inicializa um cifrador Fernet com a chave
    - Criptografa a mensagem e retorna o resultado.
"""
def codificar_mensagem(chave, message):
    fernet = Fernet(chave)
    return fernet.encrypt(message.encode())

"""
    Descriptografa a mensagem criptografada fornecida usando a chave Fernet fornecida:
    - Inicializa um cifrador Fernet com a chave
    - Descriptografa a mensagem criptografada e retorna o resultado decodificado.
"""
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
    # Cria uma thread para ouvir mensagens em segundo plano usando a função espera_por_mensagem,
    # passando o socket, o relógio, o nome de usuário (nick) e a chave para descriptografar as mensagens
    listener_thread = threading.Thread(target=espera_por_mensagem, args=(sock, relogio, nick, chave), daemon=True)
    listener_thread.start()

    # Chama a função para enviar mensagens. Esta função continuará em execução e permitirá que o usuário digite e envie mensagens.
    envia_mensagem(sock, relogio, nick, chave)

if __name__ == "__main__":
    gateway_ip = get_gateway_ip()
    if gateway_ip:
        print(f"Seu Gateway IP é: {gateway_ip}")
    else:
        print("Não foi possível determinar o Gateway IP.")
    main()