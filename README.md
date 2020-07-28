# SDN-IPS: Uma Ferramenta para Contencao de Ataques Ciberneticos Baseada em SDN

### Site do projeto: http://insert.ufba.br/sdn-ips/

## Descricao

SDN-IPS e' uma ferramenta que agrega a visibilidade dos Sistemas de Deteccao de Intrusos com a programabilidade do paradigma SDN, a fim de criar uma solucao que permita realizar a contencao de ataques ciberneticos atraves de estrategias de bloqueio, restricao de banda ou isolamento em quarentena, de forma automatizada e colaborativa.

Leia mais sobre a ferramenta no artigo [SDN-IPS: Uma Ferramenta para Contenção Automatizada e Colaborativa de Ataques Cibernéticos Baseada em SDN](http://www.sbrc2018.ufscar.br/wp-content/uploads/2018/04/180613_1.pdf), premiado como [melhor ferramenta no Salão de Ferramentas do SBRC 2018](http://www.sbrc2018.ufscar.br/salao-de-ferramentas-premio-de-melhor-artigo/).

Esta e' uma aplicacao SDN desenvolvida como resultado da [2a chamada 
Open-Call do FIBRE](https://fibre.org.br/2nd-fibre-open-call/).

## Instalação e execução

1. Instale o Ryu e dependencias do SDN-IPS:
```
apt-get install python-pip git curl python-networkx python-jsonpickle
pip install ryu
```

2. Executando o SDN-IPS
```
git clone https://github.com/italovalcy/sdn-ips
cd sdn-ips
ryu-manager --observe-links sdn-ips.py
```

## Licenciamento

O SDN-IPS e' uma ferramenta software livre; voce pode redistribui-lo e/ou modifica-lo sob os termos da Licenca Publica Geral GNU Affero (AGPL), conforme publicada pela Free Software Foundation; tanto a versao 3 da Licenca como (a seu criterio) qualquer versao posterior.

## Agradecimentos

Agradecemos ao [FIBRE](http://fibre.org.br/) e a [RNP](http://www.rnp.br) pelo financiamento deste projeto.
