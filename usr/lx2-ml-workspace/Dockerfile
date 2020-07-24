FROM mltooling/ml-workspace-spark:latest
ENV CONFIG_BACKUP_ENABLED="true" \
    SHUTDOWN_INACTIVE_KERNELS="true" \
    SHARED_LINKS_ENABLED="true" \
    AUTHENTICATE_VIA_JUPYTER="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" \
    DATA_ENVIRONMENT=$WORKSPACE_HOME"/environment" \
    WORKSPACE_BASE_URL="/" \
    INCLUDE_TUTORIALS="true" \
    WORKSPACE_PORT="8080" \
    SHELL="/usr/bin/zsh" \
    MAX_NUM_THREADS="auto"
#RUN pip install voila && \
#jupyter labextension install @jupyter-voila/jupyterlab-preview && \
#jupyter serverextension enable voila --sys-prefix
#RUN npm install -g tslab && tslab install
#RUN conda install xeus-cling -c conda-forge
#RUN conda install -c conda-forge ipywidgets beakerx
#RUN export DEBIAN_FRONTEND=noninteractive && \
#apt update && \
#apt -y install tshark
#RUN pip install pyshark nest_asyncio scapy
RUN pip install nest_asyncio
ENTRYPOINT ["/tini", "-g", "--"]
CMD ["python", "/resources/docker-entrypoint.py"]
EXPOSE 8080
