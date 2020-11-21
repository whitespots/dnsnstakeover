# Check your domain for dns zone takeover

Dont forget to pass the '--dns' flag. 
It's required to override docker dns settings

```bash
docker run --dns 8.8.8.8 --rm -e DOMAIN=site.com whitespots/dnsnstakeover

```