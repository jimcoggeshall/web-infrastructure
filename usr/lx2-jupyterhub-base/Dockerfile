FROM jupyter/all-spark-notebook
WORKDIR /home/jovyan
USER root
RUN apt-get update && \
apt-get install -y texlive-full pandoc
RUN pip install ipympl voila bokeh cython dask ipywidgets seaborn statsmodels \
sympy nltk plotly wordcloud widgetsnbextension ipyparallel xgboost datashader \
tensorflow keras pyviz holoviz numpy flatdict tldextract
RUN jupyter labextension install -y jupyter-matplotlib && \
jupyter labextension install @jupyter-widgets/jupyterlab-manager && \
jupyter labextension install @jupyterlab/katex-extension && \
jupyter labextension install @pyviz/jupyterlab_pyviz
RUN npm install -g tslab && \
tslab install
RUN groupadd -g 1002 jupyterhub
RUN mkdir -p /work && chmod -R 755 /work
COPY jupyterhub_config.py .
EXPOSE 8000
