'''
Turma 1TDCG
Professor: Fabio Cabrini
Integrantes:
Danilo da Gama Campos, RM99680
Eduardo do Nascimento Silva, RM99225
Gustavo Duarte Bezerra da Silva, RM99774
Henrique Batista de Souza, RM99742
João Eduardo Busar Pena, RM98243
'''

from flask import Flask, jsonify, request  # criar um aplicativo da web e lidar com solicitações HTTP.
import os                                  # obter informações do ambiente,
from pymongo import MongoClient            # para interagir com o MongoDB
from bson.json_util import dumps           # serializar documentos MongoDB em formato JSON.
import datetime                            # registrar carimbos de data/hora.
from scapy.all import sniff                # interceptar e analisar pacotes de rede. 
from scapy.layers.inet import IP

app = Flask(__name__)                      # cria uma instância do aplicativo Flask.

client = MongoClient(os.environ.get('DB')) # conecta o MongoDB usando as informações da variável de ambiente 'DB'
db = client.cp

# Middleware para registrar informações do cabeçalho e do pacote em MongoDB
@app.before_request        # registra informações sobre a solicitação, incluindo o método HTTP, URL, cabeçalhos e o endereço remoto do cliente
def log_request_info():
    try:
        request_info = {
            "timestamp": datetime.datetime.utcnow(),
            "method": request.method,
            "url": request.url,
            "headers": dict(request.headers),
            "remote_address": request.remote_addr,
        }

        # Adicione as informações do pacote capturado à entrada do registro
        if hasattr(request, 'packet_info'):
            request_info['packet_info'] = request.packet_info

        db.headers.insert_one(request_info)
        # print(f"Logged: {request_info}")
    except Exception as e:
        print(f"Error: {str(e)}")

# chamada sempre que um pacote de rede é interceptado. Ela extrai informações do cabeçalho IP do pacote e as armazena em um dicionário
def packet_callback(packet):
    if IP in packet:
        source_ip = packet[IP].src
        dest_ip = packet[IP].dst

        # Crie um documento com informações do cabeçalho e do pacote
        packet_info = {
            "source_ip": source_ip,
            "dest_ip": dest_ip
        }

        # Armazenar informações do pacote na solicitação atual
        request.packet_info = packet_info
        print(f"Packet information logged: {packet_info}")

# interceptação de pacotes de rede. Ele especifica que deve ser interceptado e chama a função packet_callback
def start_packet_sniffing():
    sniff(filter="ip", prn=packet_callback, store=0)

@app.route('/')
def home():
    return jsonify("Fala comigo!")

@app.route('/posts')
def posts():
    _items = db.posts.find({}, {'_id': False})
    return dumps(_items)

# O aplicativo Flask é executado na porta 5000, e a função start_packet_sniffing é chamada para iniciar a interceptação de pacotes
if __name__ == "__main__":
    try:
        app.run(host='0.0.0.0', debug=True, threaded=True)
        start_packet_sniffing()
    except Exception as e:
        print(f"Error occurred: {str(e)}")
