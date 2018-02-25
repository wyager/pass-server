openssl req -config req.cnf -new -nodes -keyout server-key.pem -out server-cert.pem -x509 -subj '/CN=localhost'
openssl req -config req.cnf -new -nodes -keyout client-key.pem -out client-cert.pem -x509 -subj '/'
