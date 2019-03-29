FROM sdrzlyz/alpine

WORKDIR /bin/

COPY ./bin/auth .

# 401 for unauth, 403 for rbac deny
EXPOSE 40103

ENTRYPOINT [ "/bin/auth" ]
CMD [ "40103" ]
