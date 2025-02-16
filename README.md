# CorsProxy

This project represents a simple CORS proxy server for your web application, which could be hosted on https://vercel.com or can be run locally.

## Vercel Usage
First, deploy the project to Vercel

Then, use the following URL as proxy URL:
```
https://<your-project-name>.vercel.app/api/proxy?url=${encodeURIComponent(urlToProxy)}
```

## Local Usage

To run CORS proxy locally on your machine, run the following command:
```bash
npx github:NotesHubApp/corsproxy
```

Local usage
```
http://localhost:5023/?url=${encodeURIComponent(urlToProxy)}
```