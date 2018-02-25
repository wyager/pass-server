
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


decodeCertsPem :: BS.ByteString -> Either String [X509.SignedCertificate]
decodeCertsPem bs = PEM.pemParseBS bs >>= mapM (X509.decodeSignedObject . PEM.pemContent)

loadCertsPem :: FilePath -> IO (Either String [X509.SignedCertificate])
loadCertsPem path = decodeCertsPem <$> BS.readFile path

loadCertPem :: FilePath -> IO (Either String X509.SignedCertificate)
loadCertPem path = onlyOne <$> loadCertsPem path 
    where 
    onlyOne parsed = parsed >>= \case 
        [] -> Left "No certs in file"
        [x] -> return x
        _ -> Left "Too many certs in file"

decodeKeyPem :: BS.ByteString -> Either String X509.PrivKey
decodeKeyPem bs =  case X509M.readKeyFileFromMemory bs of
    [] -> Left "No privkeys in file"
    [p] -> return p
    _ -> Left "Too many things in privkey file"

loadKeyPem :: FilePath -> IO (Either String X509.PrivKey)
loadKeyPem path = decodeKeyPem <$> BS.readFile path

main :: IO ()
main = do
    opts <- Opt.execParser (Opt.info (Opt.helper <*> action) Opt.fullDesc)
    case opts of
        Client certPath keyPath serverHost serverCertPath -> client certPath keyPath serverHost serverCertPath
        Server certPath keyPath clientCertsPath -> server certPath keyPath

client :: FilePath -> FilePath -> TLS.HostName -> FilePath -> IO ()
client certPath keyPath serverHost serverCertPath = do
    cert       <- either error id <$> loadCertPem certPath
    key        <- either error id <$> loadKeyPem keyPath
    serverCert <- either error id <$> loadCertPem serverCertPath
    let credential = (X509.CertificateChain [cert], key)
    res <- Wreq.getWith (managerWithCert serverHost serverCert credential) ("https://" ++ serverHost ++ "/")
    print res


managerWithCert :: TLS.HostName -> X509.SignedCertificate -> TLS.Credential -> Wreq.Options
managerWithCert hostname cert cred = Wreq.defaults & Wreq.manager .~ Left mgrSettings
    where 
    mgrSettings = TLSClient.mkManagerSettings tlsSettings Nothing
    tlsSettings = Connection.TLSSettings clientParams
    clientParams = TLS.ClientParams {
        TLS.clientUseMaxFragmentLength = Nothing,
        TLS.clientServerIdentification = (hostname, ""),
        TLS.clientUseServerNameIndication = False,
        TLS.clientWantSessionResume = Nothing,
        TLS.clientShared = def {
            TLS.sharedCAStore = X509CS.makeCertificateStore [cert],
            TLS.sharedCredentials = TLS.Credentials [cred]
        },
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
    = Client {clientCertPath :: FilePath, clientKeyPath :: FilePath, serverHost :: TLS.HostName, serverCertPath :: FilePath}
    | Server {serverCertPath :: FilePath, serverKeyPath :: FilePath, clientCertsPaths :: FilePath}

action :: Opt.Parser Action
action = client <|> server
    where
    server = Opt.flag' () serverSwitch *> serverOpts
    client = Opt.flag' () clientSwitch *> clientOpts
    serverSwitch = Opt.long "server"
                <> Opt.help "Run as server"
    clientSwitch = Opt.long "client"
                <> Opt.help "Run as client"
    serverOpts = Server <$> Opt.strOption (certPathFor "server") 
                        <*> Opt.strOption (keyPathFor "server") 
                        <*> Opt.strOption (oneOrMoreCertsPathFor "client")
    clientOpts = Client <$> Opt.strOption (certPathFor "client")
                        <*> Opt.strOption (keyPathFor "client") 
                        <*> Opt.strOption serverHost
                        <*> Opt.strOption (certPathFor "server")
    certPathFor host = Opt.long (host ++ "-cert-path" )
                    <> Opt.metavar "FILE.pem" 
                    <> Opt.help ("The PEM file containing the " ++ host ++ "'s TLS cert")
                    <> Opt.value (host ++ "-cert.pem")
                    <> Opt.showDefault
    oneOrMoreCertsPathFor host = Opt.long (host ++ "-certs-path")
                              <> Opt.metavar "FILE.pem" 
                              <> Opt.help ("The PEM file containing one or more " ++ host ++ "s' TLS certs")
                              <> Opt.value (host ++ "-cert.pem")
                              <> Opt.showDefault
    keyPathFor host = Opt.long (host ++ "-key-path")
                   <> Opt.metavar "FILE.pem" 
                   <> Opt.help ("The PEM file containing the " ++ host ++ "'s TLS key")
                   <> Opt.value (host ++ "-key.pem")
                   <> Opt.showDefault        
    serverHost = Opt.long "server-host"
              <> Opt.metavar "HOST"
              <> Opt.help "The server's hostname"
