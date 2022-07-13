namespace MyCompany.Handlers
{


    public partial class BlobFactoryConfig : BlobFactory
    {

        public static void Initialize()
        {
            // register blob handlers
            RegisterHandler("TRANSACCIONESComprobante", "\"dbo\".\"TRANSACCIONES\"", "\"COMPROBANTE\"", new string[] {
                        "\"ID_TRANSACCION\""}, "Transacciones Comprobante", "Transacciones", "Comprobante");
        }
    }
}
