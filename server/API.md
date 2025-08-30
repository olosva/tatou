# Tatou API Documentation

---

# Routes

- [create_user](#create_user) — **POST** `/api/create-user`
- [create_watermark](#create_watermark)
  - **GET** `/api/create-watermark/<int:document_id>`
  - **GET** `/api/create-watermark`
- [delete_document](#delete_document)
  - **DELETE** `/api/delete-document/<document_id>`
  - **DELETE, POST** `/api/delete-document`
- [get_document](#get_document)
  - **GET** `/api/get-document/<int:document_id>`
  - **GET** `/api/get-document`
- [get_version](#get_version) — **GET** `/api/get-version/<link>`
- [get_watermarking_methods](#get_watermarking_methods) — **GET** `/api/get-watermarking-methods`
- [healthz](#healthz) — **GET** `/healthz`
- [list_all_versions](#list_all_versions) — **GET** `/api/list-all-versions`
- [list_pdf](#list_pdf) — **GET** `/api/list-documents`
- [list_versions](#list_versions)
  - **GET** `/api/list-versions/<int:document_id>`
  - **GET** `/api/list-versions`
- [login](#login) — **POST** `/api/login`
- [read_watermark](#read_watermark)
  - **GET** `/api/read-watermark/<int:document_id>`
  - **GET** `/api/read-watermark`
- [upload_document](#upload_document) — **POST** `/api/upload-document`



## healthz

**Path**
`GET /api/healthz`

**Description**  
This endpoint checks the health of the server and confirms it is running.

**Parameters**  
_None_

**Return**
```json
{
  "message": <string>
}
```

**Specification**
 * The healthz endpoint MUST be accessible without authentication.
 * The response MUST always contain a "message" field of type string.
 
 ## create-user
 
**Path**
`POST /api/create-user`

**Description**  
This endpoint creates a new user account in the system.

**Parameters**
```json
{
  "login": <string>,
  "password": <string>,
  "email": <email>
}
```

**Return**
```json
{
  "id": <int>,
  "login": <string>,
  "email": <email>
}
```


**Specification**
 * The create-user endpoint MUST validate that username, password, and email are provided.
 * The response MUST include a unique id along with the created username and email.


## login

**Path**
`POST /api/login`

**Description**  
This endpoint authenticates a user with their credentials and returns a session token.

**Parameters**
```json
{
  "email": <string>,
  "password": <string>
}
```

**Return**
```json
{
  "token": <string>,
  "token_type": "bearer",
  "expires_in": <int>
}
```

**Specification**
 * The login endpoint MUST reject requests missing email or password.
 * The response MUST include a token string and its expiration date as an integer Time To Live in seconds.
 
 ## upload-document

**Path**
`POST /api/upload-document`

**Description**  
This endpoint uploads a PDF document to the server and registers its metadata.

**Parameters**
```json
{
  "file": <pdf file>,
  "name": <string>
}
```

**Return**
```json
{
  "id": <string>,
  "name": <string>,
  "creation": <date ISO 8601>,
  "sha256": <string>,
  "size": <int>
}
```

**Specification**
 * Requires authentication
 * The upload-pdf endpoint MUST accept only files in PDF format.

## list-documents

**Path**
`GET /api/list-documents`

**Description**  
This endpoint lists all uploaded PDF documents along with their metadata.

**Parameters**  
_None_

**Return**
```json
{
  "documents": [
    {
      "id": <string>,
      "name": <string>,
      "creation": <date ISO 8601>,
      "sha256": <string>,
      "size": <int>
    }
  ]
}
```

**Specification**
 * Requires authentication
 * The response MUST return all documents of the user.
 
 ## list-versions

**Description**  
This endpoint lists all watermarked versions of a given PDF document along with their metadata.

**Path**
`GET /api/list-versions`

**Parameters**
```json
{
  "documentid": <int>
}
```

**Path**
`GET /api/list-versions/<int:document_id>`

**Parameters**  
_None_

**Return**
```json
{
  "versions": [
    {
      "id": <string>,
      "documentid": <string>,
      "link": <string>,
      "intended_for": <string>,
      "secret": <string>,
      "method": <string>
    }
  ]
}
```



**Specification**
 * Requires authentication
 
 
 ## list-all-versions
 
**Path**
`GET /api/list-versions`

**Description**  
This endpoint lists all versions of all PDF documents for the authenticated user stored in the system.

**Parameters**  
_None_

**Return**
```json
{
  "versions": [
    {
      "id": <string>,
      "documentid": <string>,
      "link": <string>,
      "intended_for": <string>,
      "secret": <string>,
      "method": <string>
    }
  ]
}
```

**Specification**
 * Requires authentication
 
 ## get-document
 
**Description**  
This endpoint retrieves a PDF document by fetching a specific one when an `id` is provided.
 
**Path**
`GET /api/get-document`


**Parameters**
```json
{
  "id": <int>
}
```

**Path**
`GET /api/get-document/<int:document_id>`

**Return**
Inline PDF file in binary format.

**Specification**
 * Requires authentication
