package actuator
import("context";"net/http";"net/http/httptest";"net/url";"strconv";"testing")
func TestLeadM180EmptyInventoryIsNotLoaded(t *testing.T){
 for _,tc:=range []struct{name,body string;want bool}{{"empty",`{"data":[]}`,false},{"loaded-positive",`{"data":[{"id":"model-a"}]}`,true}}{t.Run(tc.name,func(t *testing.T){
  health,models,posts:=0,0,0
  server:=httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){if r.Method!="GET"{posts++;w.WriteHeader(405);return};switch r.URL.Path{case"/health":health++;w.Write([]byte(`{}`));case"/v1/models":models++;w.Header().Set("Content-Type","application/json");w.Write([]byte(tc.body));default:w.WriteHeader(404)}}));defer server.Close()
  u,_:=url.Parse(server.URL);port,_:=strconv.Atoi(u.Port());ep:=servingEndpoint{podIP:u.Hostname(),port:port,healthPath:"/health",modelsPath:"/v1/models"}
  got,err:=(&httpVLLM{hc:server.Client()}).ModelReady(context.Background(),ep)
  if health!=1||models!=1||posts!=0{t.Fatalf("wrong producer path health=%d models=%d posts=%d",health,models,posts)}
  if err!=nil{t.Fatalf("complete valid inventory got error: %v",err)}
  if got!=tc.want{t.Errorf("actual health200 plus %s inventory ModelReady=%v want %v",tc.name,got,tc.want)}
 })}
}
