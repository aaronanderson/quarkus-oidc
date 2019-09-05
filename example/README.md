## Overview

This example illustrates how to add, configure, and run the Quarkus OIDC extension.  

## Execution

Ensure NodeJS and yarn are installed.

```
yarn
yarn build
mvn compile quarkus:dev
```


run the following command to monitor for local file changes and automatically trigger a webpack build:

`yarn watch`

when combined with the quarkus:dev maven command web content development can be performed with realtime updates. 

## Configuration

If you add additional react pages be sure to edit the `src/main/resources/META-INF/undertow-handlers.conf` and map the new page URL to index.html. This way if a user refreshes a page with a rewritten URL the page will be rendered instead of a 404 file not found error being returned.

The OIDC Quarkus extensions is configured by settings in the `src/main/resources/application.properties` file.

Enable OIDC redirects by removing the line:

`quarkus.oidc.default-claims.enabled=true`

Optionally comment or remove all of the other default-claim lines.

and then properly configure the lines:

```
quarkus.oidc.issuer=
quarkus.oidc.client-id= 
quarkus.oidc.client-secret= 
```

Also be sure to skip tests when running the example application with an OIDC IDP configured since the rest client cannot perform OIDC browser based authentication and automated tests will fail:

`mvn clean install quarkus:dev -DskipTests`


## Initial Setup

Below is an example of how to setup a new React JS application

```
mvn io.quarkus:quarkus-maven-plugin:0.21.1:create \
    -DprojectGroupId=com.github.quarkus.oidc \
    -DprojectArtifactId=example \
    -DprojectVersion=2019.9.0-SNAPSHOT \
    -DclassName="com.github.quarkus.ExampleResource"
    cd example

yarn add --dev webpack
yarn add --dev webpack-cli
yarn add --dev html-webpack-plugin 

yarn add --dev @babel/preset-react
yarn add react react-dom
yarn add @reach/router
yarn add axios

yarn add --dev autoprefixer
yarn add --dev file-loader html-loader

#typescript support
yarn add --dev @types/react @types/react-dom
yarn add --dev typescript ts-loader source-map-loader
yarn add @types/reach__router @types/react-router-dom
```

Edit the `webpack.config.js` and `tsconfig.json` file and set the custom source and build paths as needed to support the maven project layout.

react-scripts could be used to generate a sample project but in order to configure custom source and paths the eject command should be run to expose all the configuration files for modification. A large number of modules are referenced and it may be excessive for most projects.

```
cd example    
npx create-react-app quarkus-react
mv quarkus-react/src*/ src/main/web
mv quarkus-react/* quarkus-react/.* .
yarn build
yarn eject
```
