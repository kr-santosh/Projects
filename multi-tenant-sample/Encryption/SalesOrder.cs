namespace Cosmos.Samples.Encryption
{
    using System;
    using Newtonsoft.Json;

    public class SalesOrderDetail
    {
        public int OrderQty { get; set; }
        public int ProductId { get; set; }
        public decimal UnitPrice { get; set; }
        public decimal LineTotal { get; set; }
    }

    public class SalesOrder
    {
        [JsonProperty(PropertyName = "id")]
        public string Id { get; set; }

        [JsonProperty(PropertyName = "ponumber")]
        public string PurchaseOrderNumber { get; set; }

        // used to set expiration policy
        [JsonProperty(PropertyName = "ttl", NullValueHandling = NullValueHandling.Ignore)]
        public int? TimeToLive { get; set; }

        public DateTime OrderDate { get; set; }

        public string AccountNumber { get; set; }

        public decimal SubTotal { get; set; }

        public decimal Freight { get; set; }

        public decimal TotalDue { get; set; }

        public SalesOrderDetail[] Items { get; set; }
    }

}
