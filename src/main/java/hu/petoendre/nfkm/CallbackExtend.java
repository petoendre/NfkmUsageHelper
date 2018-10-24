package hu.petoendre.nfkm;
import com.ncipher.km.nfkm.DefaultCallBack;
import com.ncipher.nfast.NFException;

public class CallbackExtend extends DefaultCallBack {
  final private String password;
  
  
  public CallbackExtend(String password) {
    super();
    this.password = password;
  }


  public String reqPPCallBack(String paramString)
    throws NFException
  {
    return password;
  }

}
