openssl genrsa -aes128 -passout pass:"test123" -out private.pem 4096
openssl rsa -in private.pem -passin pass:"test123" -pubout -out public.pem

