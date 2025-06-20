select * from dbo.FacturasDGII
select * from dbo.ItemsFactura

--delete from dbo.FacturasDGII
--delete from dbo.ItemsFactura

select * from dbo.FacturasDGII as a
inner join dbo.ItemsFactura as b
on a.id = b.FacturaId
WHERE A.id = '33'


where ENCF = 'E310000000075'