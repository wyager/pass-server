
-- General
import qualified Data.ByteString as BS
import qualified Data.Text as Text
import qualified Data.Text.IO as TextIO
import Data.Monoid ((<>))
import Control.Applicative ((<|>))
import Control.Monad (when)
import GHC.Generics (Generic)
import qualified Data.Aeson as Aeson
import qualified Data.Tree as Tree
import qualified Path
import Data.List (intercalate)
-- PEM loading
import qualified Data.X509 as X509
import qualified Data.X509.CertificateStore as X509CS
import qualified Data.X509.Memory as X509M
import qualified Data.PEM as PEM
-- Client
import qualified Network.Wreq as Wreq
import Control.Lens ((&), (.~), (%~), _Left)
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
import qualified Network.HTTP.Types.Header as Headers
import qualified System.Directory.Tree as DirTree
import qualified System.Process as Proc
-- Command line
import qualified Options.Applicative as Opt

type Request = Path.Path Path.Rel Path.File

data PassError = NotFound | NoHandle 
    deriving stock Generic
    deriving anyclass (Aeson.ToJSON, Aeson.FromJSON)

data Response = Error PassError | Password Text.Text | Directory (Tree.Tree FilePath) 
    deriving stock Generic
    deriving anyclass (Aeson.ToJSON, Aeson.FromJSON)

data Action
    = Client { clientCertPath :: FilePath
             , clientKeyPath :: FilePath
             , serverHost :: TLS.HostName
             , serverCertPath :: FilePath
             , request :: Request}
    | Server { serverCertPath :: FilePath
             , serverKeyPath :: FilePath
             , clientCertsPaths :: FilePath
             , passDir :: FilePath
             , passBinaryLocation :: FilePath}

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
                        <*> Opt.strOption passDir
                        <*> Opt.strOption passBinaryLoc
    clientOpts = Client <$> Opt.strOption (certPathFor "client")
                        <*> Opt.strOption (keyPathFor "client") 
                        <*> Opt.strOption serverHost
                        <*> Opt.strOption (certPathFor "server")
                        <*> Opt.option (Opt.eitherReader parseRelFile) request
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
    passDir = Opt.long "pass-dir"
           <> Opt.metavar "PATH"
           <> Opt.help "The root directory of the pass installation"
           <> Opt.value ("~/.password-store/")
    passBinaryLoc = Opt.long "pass-binary"
                 <> Opt.metavar "PATH"
                 <> Opt.help "The location of the pass binary"
                 <> Opt.value ("/usr/bin/pass")
    parseRelFile = (_Left %~ show) . Path.parseRelFile
    request = Opt.long "request"
           <> Opt.metavar "PATH"
           <> Opt.help "The path to the (set of) passwords you want"

main :: IO ()
main = do
    opts <- Opt.execParser (Opt.info (Opt.helper <*> action) Opt.fullDesc)
    case opts of
        Client certPath keyPath serverHost serverCertPath request -> 
            client certPath keyPath serverHost serverCertPath request
        Server certPath keyPath clientCertsPath passDir passBinary -> 
            server certPath keyPath clientCertsPath passDir passBinary


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


client :: FilePath -> FilePath -> TLS.HostName -> FilePath -> Request -> IO ()
client certPath keyPath serverHost serverCertPath request = do
    cert       <- either error id <$> loadCertPem certPath
    key        <- either error id <$> loadKeyPem keyPath
    serverCert <- either error id <$> loadCertPem serverCertPath
    let credential = (X509.CertificateChain [cert], key)
        path = "https://" ++ serverHost ++ "/" ++ Path.toFilePath request
    res <- Wreq.getWith (managerWithCert serverHost serverCert credential) path
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
        TLS.clientHooks = def {TLS.onCertificateRequest = \_ -> return (Just cred)}, 
        TLS.clientSupported = def {TLS.supportedCiphers = TLSE.ciphersuite_strong},
        TLS.clientDebug = def
    }

server :: FilePath -> FilePath -> FilePath -> FilePath -> FilePath -> IO ()
server certPath keyPath clientCertsPath passDir passBinary = do
    allowedCerts <- either error id <$> loadCertsPem clientCertsPath
    let checkCertChain certChain = if any (== certChain) (map (\cert -> X509.CertificateChain [cert]) allowedCerts)
            then TLS.CertificateUsageAccept
            else TLS.CertificateUsageReject TLS.CertificateRejectUnknownCA
    WarpTLS.runTLS (tlsSettings checkCertChain) settings (serverApp passDir passBinary)
    where
    tlsSettings checkCertChain =  (WarpTLS.tlsSettings certPath keyPath) {
        WarpTLS.tlsWantClientCert = True,
        WarpTLS.tlsServerHooks = def {
            TLS.onClientCertificate = (return . checkCertChain)
        }
    }
    settings = Warp.defaultSettings

serverApp :: FilePath -> FilePath -> Wai.Application
serverApp root passBin req send = do
    let path = Wai.pathInfo req
        dangerous path = Text.any (== '/') path || path == ".."
    -- Not worrying about this too much, since if someone has gotten this far they have
    -- already compromised our certificate infra
    when (any dangerous path) (error "Path contains dangerous stuff") 
    let fullpath = root ++ "/" ++ intercalate "/" (map Text.unpack path)
    anchodr DirTree.:/ dirTree <- DirTree.readDirectoryWith return fullpath
    resp <- dirTreeToResp (loadPassWith passBin) dirTree
    send (Wai.responseLBS Status.status200 [] (Aeson.encode resp))

dirTreeToResp :: (FilePath -> IO (Either PassError Text.Text)) -> DirTree.DirTree FilePath -> IO Response
dirTreeToResp loadPassAt dir = case dir of 
            DirTree.Failed _ _ -> return $ Error NotFound
            DirTree.Dir name contents -> return (Directory (go name contents))
            DirTree.File name path -> do
                pass <- loadPassAt path
                return $ either Error Password pass
    where
    go name contents = Tree.Node name $ concatMap go' contents
    go' (DirTree.Failed _ _) = []
    go' (DirTree.Dir name contents) = [go name contents]
    go' (DirTree.File name path) = [go name []]

loadPassWith :: FilePath -> FilePath -> IO (Either PassError Text.Text)
loadPassWith binary path = do
    let process = Proc.proc binary [path]
    (_, stdout, _, _) <- Proc.createProcess process
    case stdout of 
        Nothing -> return $ Left NoHandle 
        Just stdout -> do
            output <- TextIO.hGetContents stdout
            let errorStart = "Error: "
                errorEnd = " is not in the password store.\n"
            if Text.take (Text.length errorStart) output == errorStart &&
                Text.take (Text.length errorEnd) output == errorEnd
            then return $ Left NotFound
            else return $ Right output 
    
