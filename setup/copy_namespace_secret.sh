kubectl get secret malwaretl-cluster-es-elastic-user -n es -o yaml | grep -v '^\s*namespace:\s' | kubectl apply -n transformers -f -