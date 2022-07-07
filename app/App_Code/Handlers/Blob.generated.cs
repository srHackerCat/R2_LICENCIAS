namespace MyCompany.Handlers
{


    public partial class BlobFactoryConfig : BlobFactory
    {

        public static void Initialize()
        {
            // register blob handlers
            RegisterHandler("TRANSACCIONComprobante", "\"dbo\".\"TRANSACCION\"", "\"COMPROBANTE\"", new string[] {
                        "\"ID_TRANSACCION\""}, "Transaccion Comprobante", "Transaccion", "Comprobante");
        }
    }
}
