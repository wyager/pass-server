
-- General
import qualified Data.ByteString as BS
import Data.Monoid ((<>))
import Control.Applicative ((<|>))
-- PEM loading
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509CS
import qualified Data.X509.Memory as X509M
import qualified Data.PEM as PEM
-- Client
import qualified Network.Wreq as Wreq
import Control.Lens ((&), (.~))
import qualified Network.HTTP.Client.TLS as TLSClient
import qualified Network.Connection as Connection
import qualified Network.TLS as TLS
import qualified Network.TLS.Extra as TLSE
import Network.Socket (HostName)
import Data.Default (def)
-- Server
import qualified Network.Wai.Handler.Warp as Warp
import qualified Network.Wai.Handler.WarpTLS as WarpTLS
import qualified Network.Wai as Wai
import qualified Network.HTTP.Types.Status as Status
import qualified Network.HTTP.Types.Header as Header
-- Command line
import qualified Options.Applicative as Opt


parseOnePem :: BS.ByteString -> Either String PEM.PEM
parseOnePem bs = PEM.pemParseBS bs >>= \case
    [] -> Left "Empty PEM data"
    [x] -> return x
    _ -> Left "Too many PEM sections"


decodeCertPem :: BS.ByteString -> Either String X509.SignedCertificate
decodeCertPem bs = parseOnePem bs >>= (X509.decodeSignedObject . PEM.pemContent)

decodeKeyPem :: BS.ByteString -> Either String X509.PrivKey
decodeKeyPem bs =  case X509M.readKeyFileFromMemory bs of
    [] -> Left "No privkeys in file"
    [p] -> return p
    _ -> Left "Too many things in privkey file"

loadCertPem :: FilePath -> IO (Either String X509.SignedCertificate)
loadCertPem path = decodeCertPem <$> BS.readFile path

loadKeyPem :: FilePath -> IO (Either String X509.PrivKey)
loadKeyPem path = decodeKeyPem <$> BS.readFile path

main :: IO ()
main = do
    opts <- Opt.execParser (Opt.info (Opt.helper <*> action) Opt.fullDesc)
    case opts of
        Client certPath serverHost -> client certPath serverHost
        Server certPath keyPath -> server certPath keyPath

client :: FilePath -> TLS.HostName -> IO ()
client certPath server = do
    cert <- either error id <$> loadCertPem certPath
    res <- Wreq.getWith (managerWithCert server cert) ("https://" ++ server ++ "/")
    print res


managerWithCert :: TLS.HostName -> X509.SignedCertificate -> Wreq.Options
managerWithCert hostname cert = Wreq.defaults & Wreq.manager .~ Left mgrSettings
    where 
    mgrSettings = TLSClient.mkManagerSettings tlsSettings Nothing
    tlsSettings = Connection.TLSSettings clientParams
    clientParams = TLS.ClientParams {
        TLS.clientUseMaxFragmentLength = Nothing,
        TLS.clientServerIdentification = (hostname, ""),
        TLS.clientUseServerNameIndication = False,
        TLS.clientWantSessionResume = Nothing,
        TLS.clientShared = def {TLS.sharedCAStore = X509CS.makeCertificateStore [cert]},
        -- NB: I think I need to modify clientHooks onServerCertificate to rule out anything besides [cert]
        TLS.clientHooks = def, 
        TLS.clientSupported = def {TLS.supportedCiphers = TLSE.ciphersuite_strong},
        TLS.clientDebug = def
    }

server :: FilePath -> FilePath -> IO ()
server certPath keyPath = WarpTLS.runTLS tlsSettings settings serverApp
    where
    tlsSettings =  WarpTLS.tlsSettings certPath keyPath
    settings = Warp.defaultSettings

serverApp :: Wai.Application
serverApp req send = send (Wai.responseLBS Status.status200 [] "lookin' good")

data Action
    = Client {serverCertPath :: FilePath, serverHost :: TLS.HostName}
    | Server {serverCertPath :: FilePath, serverKeyPath :: FilePath}

action :: Opt.Parser Action
action = client <|> server
    where
    server = Opt.flag' () serverSwitch *> (Server <$> Opt.strOption serverCertPath <*> Opt.strOption serverKeyPath)
    serverSwitch = Opt.long "server"
                <> Opt.help "Run as server"
    client = Opt.flag' () clientSwitch *> (Client <$> Opt.strOption serverCertPath <*> Opt.strOption serverHost)
    clientSwitch = Opt.long "client"
                <> Opt.help "Run as client"
    serverCertPath = Opt.long "cert-path" 
                  <> Opt.metavar "FILE.pem" 
                  <> Opt.help "The PEM file containing the server's TLS cert"
                  <> Opt.value "cert.pem"
                  <> Opt.showDefault
    serverKeyPath = Opt.long "key-path" 
                  <> Opt.metavar "FILE.pem" 
                  <> Opt.help "The PEM file containing the server's TLS key"
                  <> Opt.value "key.pem"
                  <> Opt.showDefault        
    serverHost = Opt.long "server-host"
              <> Opt.metavar "HOST"
              <> Opt.help "The server's hostname"
