	## Build temporary image layer, using ASP.NET Core SDK's image
	FROM microsoft/dotnet:2.1-sdk AS build-env
	WORKDIR /app
	## Copy csproj and restore as distinct layers
	COPY *.csproj ./
	RUN dotnet restore
	## Copy everything else and build
	COPY . ./
	RUN dotnet publish -c Release -o out
	## Build runtime image, using ASP.NET Core Runtime's image
	FROM microsoft/dotnet:2.1-aspnetcore-runtime
	WORKDIR /app
	COPY --from=build-env /app/out .
	## Configure for using a specific customize container listening port (default port is 80)
	#EXPOSE 5000/tcp
	#ENV ASPNETCORE_URLS=http://+:5000
	ENV ASPNETCORE_URLS="https://+;http://+"
	ENV ASPNETCORE_HTTPS_PORT=8001
	ENV ASPNETCORE_Kestrel__Certificates__Default__Password="password"
	ENV ASPNETCORE_Kestrel__Certificates__Default__Path=/https/undone.pfx
ENTRYPOINT ["dotnet", "Undone.Auth.dll"]