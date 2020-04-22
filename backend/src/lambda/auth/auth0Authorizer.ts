import { CustomAuthorizerEvent, CustomAuthorizerResult } from 'aws-lambda'
import 'source-map-support/register'

// import { verify, decode } from 'jsonwebtoken'
import { verify } from 'jsonwebtoken'
import { createLogger } from '../../utils/logger'
// import Axios from 'axios'
// import { Jwt } from '../../auth/Jwt'
import { JwtPayload } from '../../auth/JwtPayload'

const logger = createLogger('auth')

// TODO: Provide a URL that can be used to download a certificate that can be used
// to verify JWT token signature.
// To get this URL you need to go to an Auth0 page -> Show Advanced Settings -> Endpoints -> JSON Web Key Set
// const jwksUrl = ''
const cert = `-----BEGIN CERTIFICATE-----
MIIDFzCCAf+gAwIBAgIJePmUIjw0/YDCMA0GCSqGSIb3DQEBCwUAMCkxJzAlBgNV
BAMTHnNpbmRodS1zZXJ2ZXJsZXNzLmV1LmF1dGgwLmNvbTAeFw0yMDA0MjAwMDI3
NDJaFw0zMzEyMjgwMDI3NDJaMCkxJzAlBgNVBAMTHnNpbmRodS1zZXJ2ZXJsZXNz
LmV1LmF1dGgwLmNvbTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAMZr
EIiYHDyqkRK83FBNvFoixtMEHr51mHXWdY6hV96EC5O0q9JYt/T2J03E80a0UDwb
Ik0/Xi7bFZGRejUdEdOxIwmjA3GV+RnEjQh2FdFPvwNeTJprhcFBVnbYxrnFVe7B
Ix+U7cgvu1HStNjo0JLOA6rICsqbxZaneOUPBhViVv9mt4f4RPDzCYWCHeTWslEQ
0sOrbFMiLDsfWCjQDM2ZiXKc0/ag4ZywBQDN5SzoHvInCYgfvVnVE6VZI9IblQKG
4Byrfm6dI4nZ91pnoqZV9vOXprlU1VOjKFxPU32nfPore6MVW72CgU9bau54+7bW
rx1TrGP+XQuXnpU9Py8CAwEAAaNCMEAwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4E
FgQUo3f91sTKTpOcErewRVYg1jo9oxEwDgYDVR0PAQH/BAQDAgKEMA0GCSqGSIb3
DQEBCwUAA4IBAQAcrjdeHTjHT4t2cec5bKNgaIttJnM/XlJdpGG8rVETOif+pUtb
Gl70dSaeoGcbzF1PBkrIfP12j/XRA7g7uv8XCf4Kufp+kMEUFrIKpmK3xRXZQu8h
yLJ3RbJQ6Kr80SwVg+yN+nzdeOm7Fl4TpL6aNV0knn7oAT8sEfsUT2q8qX7ngPrJ
rBPgnbj2WttlyaYcPrxKUVCPlvNjBYPxVqJXM6pJyYUAVoliTdDv70MDqEV6Gx2U
uP246XWT7xQRycqDBkZ/S1cwGT7khP6rBJ68AighFqNYnv6s2JDoAVm+XoFmjpPp
iDdxUcSbPadpKP2IhsiM+bPJpHLPFHu3h+xP
-----END CERTIFICATE-----`

export const handler = async (event: CustomAuthorizerEvent): Promise<CustomAuthorizerResult> => {
  logger.info('Authorizing a user', event.authorizationToken)
  try {
    const jwtToken = await verifyToken(event.authorizationToken)
    logger.info('User was authorized', jwtToken)

    return {
      principalId: jwtToken.sub,
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Allow',
            Resource: '*'
          }
        ]
      }
    }
  } catch (e) {
    logger.error('User not authorized', { error: e.message })

    return {
      principalId: 'user',
      policyDocument: {
        Version: '2012-10-17',
        Statement: [
          {
            Action: 'execute-api:Invoke',
            Effect: 'Deny',
            Resource: '*'
          }
        ]
      }
    }
  }
}

async function verifyToken(authHeader: string): Promise<JwtPayload> {
  const token = getToken(authHeader)
  // const jwt: Jwt = decode(token, { complete: true }) as Jwt

  // Implement token verification
  // You should implement it similarly to how it was implemented for the exercise for the lesson 5
  // You can read more about how to do this here: https://auth0.com/blog/navigating-rs256-and-jwks/
  return  verify(token, cert, { algorithms: ['RS256'] }) as JwtPayload
}

function getToken(authHeader: string): string {
  if (!authHeader) throw new Error('No authentication header')

  if (!authHeader.toLowerCase().startsWith('bearer '))
    throw new Error('Invalid authentication header')

  const split = authHeader.split(' ')
  const token = split[1]

  return token
}
