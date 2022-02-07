FROM dzhuang/parent_control-base
MAINTAINER Dong Zhuang <dzhuang.scut@gmail.com>

ARG USERNAME=pc_user

COPY --chown=$USERNAME parent_control /opt/parent_control/

WORKDIR /opt/parent_control/
VOLUME /opt/parent_control/local_settings

EXPOSE 8030

# Start server
STOPSIGNAL SIGTERM

USER $USERNAME

CMD ["/opt/parent_control/start-server.sh"]
