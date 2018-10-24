package hu.petoendre.nfkm;
import java.io.IOException;
import com.ncipher.jutils.Passphrase;
import com.ncipher.km.nfkm.DefaultCallBack;
import com.ncipher.km.nfkm.SoftCard;
import com.ncipher.nfast.NFException;

public class WorldCallbacks extends DefaultCallBack {
  public SoftCard configured_softcard = null;
  public String reqPPCallBack(String ReqPPAction) throws NFException {
  try {
  return Passphrase.readPassphrase("Enter softcard pass phrase: ");
  } catch(IOException e) {
  throw new NFException(e.toString());
  }
  }
  // Callback to choose a softcard
  public SoftCard getSoftCardCallback() throws NFException {
  return configured_softcard;
  };

}
