# istio auth adapter

### `auth-adapter` is JWT token with redis block strategy and RBAC combination for istio mixer.

### please read reference first to know more about istio `template` and `adapter`.
> https://github.com/istio/istio/wiki/Mixer-Out-Of-Process-Adapter-Walkthrough
> https://github.com/istio/istio/wiki/Mixer-Template-Dev-Guide
> https://github.com/istio/istio/wiki/Route-directive-adapter-development-guide

#### dev steps https://github.com/istio/istio/wiki/Dev-Guide
```
# clone istio to go path
mkdir -p $GOPATH/src/istio.io
git clone https://github.com/istio/istio $GOPATH/src/istio.io/istio

# clone this repo as auth dir
git clone https://github.com/libgo/istio-auth-adapter $GOPATH/src/istio.io/isito/mixer/adapter/auth

cd $GOPATH/src/istio.io/isito/mixer/adapter/auth
make gen
make build
```

#### deploy steps:
```
kubectl apply -f ./attributes.yaml
kubectl apply -f ./template.yaml
kubectl apply -f ./config/auth-adapter.yaml
kubectl apply -f ./cluster-service.yaml # change replica and image as you need.
kubectl apply -f ./operator-cfg.yaml # change match as you need.
```

#### Introduction
```
header:
  x-token for raw jwt token.
  x-token-verify=1 for adaprer verify mark.


server os.env params:
  jwt_ecdsa_public: base64 encoded pub key for ecdsa
  jwt_ecdsa_private: base64 encoded pri key for ecdsa
```

// TODO
```
0、more configurable
1、jwt redis block
2、RBAC
```
