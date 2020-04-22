//  API id used by the frontend to interact with the backend
const apiId = 'm3hxo5rvg8'
export const apiEndpoint = `https://${apiId}.execute-api.eu-west-1.amazonaws.com/dev`

export const authConfig = {
  //Auth0 application values
  domain: 'sindhu-serverless.eu.auth0.com',            // Auth0 domain
  clientId: 'xBR4x26ZNV7hiJWtBHXk6aG6eASI4dlO',          // Auth0 client id
  callbackUrl: 'http://localhost:3000/callback'
}
