# es-ksm

Keystore manager of sorts for Elasticsearch (given that you're using bare metal hosts for your nodes and using the puppet module with CentOS, otherwise you'll have to make minor modifications). Give it a cluster API, the verb and other required params and it'll reach out to the keystore(s) where applicable.

Used with CentOS 7.x with nodes setup on bare metal hosts using forge module for Elasticsearch, tested against 5/6.x (up to 6.4.x) clusters. You may need to make modifications if using it outside this configuration.

## Usage

```
usage: ksm.py [-h] [--input-file [INPUT_FILE]] --es-host ES_HOST
              [--es-user ES_USER] [--es-pass ES_PASS]
              {add,add-file,remove,list,create} [key_value [key_value ...]]

positional arguments:
  {add,add-file,remove,list,create}
  key_value             key (and value if applicable in the form of key=value)

optional arguments:
  -h, --help            show this help message and exit
  --input-file [INPUT_FILE]
                        file for add-file verb
  --es-host ES_HOST     es api
  --es-user ES_USER     es user
  --es-pass ES_PASS     es pass
```

## Examples

Doing some adding/removing/listing.

```
$ python ksm.py add something=else else=something --es-host https://es-stage-api.example.com
Password: 
es-stage_client10 something=else ✔
es-stage_client07 something=else ✔
es-stage_data04   something=else ✔
es-stage_client06 something=else ✔
es-stage_data05   something=else ✔
es-stage_data03   something=else ✔
es-stage_client08 something=else ✔
es-stage_data02   something=else ✔
es-stage_data01   something=else ✔
es-stage_client09 something=else ✔
es-stage_master01 something=else ✔
es-stage_master03 something=else ✔
es-stage_master05 something=else ✔
es-stage_master02 something=else ✔
es-stage_master04 something=else ✔
es-stage_client10 else=something ✔
es-stage_client07 else=something ✔
es-stage_data04   else=something ✔
es-stage_client06 else=something ✔
es-stage_data05   else=something ✔
es-stage_data03   else=something ✔
es-stage_data01   else=something ✔
es-stage_data02   else=something ✔
es-stage_client08 else=something ✔
es-stage_client09 else=something ✔
es-stage_master01 else=something ✔
es-stage_master03 else=something ✔
es-stage_master05 else=something ✔
es-stage_master02 else=something ✔
es-stage_master04 else=something ✔
$ python ksm.py remove something else --es-host https://es-stage-api.example.com
Password: 
es-stage_data04   ✔
es-stage_client10 ✔
es-stage_client07 ✔
es-stage_client06 ✔
es-stage_data01   ✔
es-stage_data03   ✔
es-stage_data05   ✔
es-stage_data02   ✔
es-stage_client08 ✔
es-stage_client09 ✔
es-stage_master01 ✔
es-stage_master02 ✔
es-stage_master03 ✔
es-stage_master05 ✔
es-stage_master04 ✔
$ python ksm.py list --es-host https://es-stage-api.example.com                 
Password: 
es-stage_client07:
 - keystore.seed
 - s3.client.default.endpoint
 - s3.client.minio.endpoint
es-stage_client10:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_client06:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_data04:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_client08:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_data05:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_data01:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_master01:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_client09:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_data02:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_data03:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_master03:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_master05:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_master02:
 - keystore.seed
 - s3.client.minio.endpoint
es-stage_master04:
 - keystore.seed
 - s3.client.minio.endpoint
```

## Todo

- [ ] maybe check the input arguments for `-Des.path.conf=...` and use that path instead? Might be more reliable than assuming the path based on the node name
