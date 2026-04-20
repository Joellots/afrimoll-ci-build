# syntax=docker/dockerfile:1

# ---- Serve Stage ----
# The build has already been performed by the pipeline (npm run build)
# and dist/ is the only thing copied into this image's context.
FROM nginx:alpine

COPY dist/ /usr/share/nginx/html/
COPY nginx.conf /etc/nginx/conf.d/default.conf

EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
