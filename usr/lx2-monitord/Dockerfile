FROM jupyter/all-spark-notebook:latest

USER root
RUN export DEBIAN_FRONTEND=noninteractive && \
apt update && \
apt -y install dnsutils \
vim \
whois \
net-tools \
socat

USER $NB_UID
RUN conda install -c conda-forge xeus-cling \
ipywidgets \
beakerx \
bokeh
RUN conda install -c conda-forge -c plotly jupyter-dash
RUN pip install voila \
"holoviews[recommended]" \
sidecar && \
jupyter labextension install --no-build jupyterlab-drawio && \
jupyter labextension install --no-build @jupyter-voila/jupyterlab-preview && \
jupyter labextension install --no-build @jupyter-widgets/jupyterlab-manager && \
jupyter labextension install --no-build @bokeh/jupyter_bokeh && \
jupyter labextension install --no-build @pyviz/jupyterlab_pyviz && \
jupyter labextension install --no-build @jupyter-widgets/jupyterlab-manager && \
jupyter labextension install --no-build @jupyter-widgets/jupyterlab-sidecar && \
jupyter labextension install --no-build @jupyterlab/toc && \
jupyter labextension install --no-build @jupyterlab/server-proxy && \
jupyter serverextension enable voila --sys-prefix
RUN npm install -g tslab && \
tslab install

RUN conda clean --all -f -y && \
fix-permissions "${CONDA_DIR}" && \
fix-permissions "/home/${NB_USER}"

RUN jupyter lab build

RUN pip install nest_asyncio \
ipwhois \
py-radix \
websockets \
tldextract

ADD monitor.py ip2asn-v4.tsv ip-protocol-numbers.json ports.csv /home/jovyan/work/
