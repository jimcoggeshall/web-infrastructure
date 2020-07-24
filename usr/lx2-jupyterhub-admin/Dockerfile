FROM lx2-jupyterhub-base
WORKDIR /home/jovyan
USER root
RUN useradd user -m -d /work/user -g jupyterhub -p 'XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX'
COPY run .
EXPOSE 8000
ENTRYPOINT ["/home/jovyan/run"]
