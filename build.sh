go generate -tags lc_syn ./cmd/lb
go build -tags lc_syn -o lb_lc_syn ./cmd/lb
go generate -tags lc_est ./cmd/lb
go build -tags lc_est -o lb_lc_est ./cmd/lb
go generate -tags wlc_est ./cmd/lb
go build -tags wlc_est -o lb_wlc_est ./cmd/lb
go generate -tags wlc_syn ./cmd/lb
go build -tags wlc_syn -o lb_wlc_syn ./cmd/lb

