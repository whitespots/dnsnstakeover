# A small contribution to community :)
This is a part of our toolset for [vulneravility monitoring service](https://whitespots.io/vulnerability-monitoring)

### Check other [opensource tools](https://github.com/whitespots/fast-security-scanners)

# Check your domain for dns zone takeover

Dont forget to pass the '--dns' flag. 
It's required to override docker dns settings

```bash
docker run --dns 8.8.8.8 --rm -e DOMAIN=site.com whitespots/dnsnstakeover

```
