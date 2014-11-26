%define majorminor   1.0

%{!?gstreamer:  %define         gstreamer       gstreamer}

Name:		%{gstreamer}-cenc
Version:	0.0.1
Release:	1.cenc
Summary:	GStreamer plug-in to handle DASH common encryption

Group:		Applications/Multimedia
License:	Commercial
URL:		http://www.youview.com/
Source:		gst-cenc-%{version}.tar.bz2
BuildRoot:      %{_tmppath}/%{name}-%{version}-%{release}-root-%(%{__id_u} -n)

BuildRequires:  pkgconfig
BuildRequires:  %{gstreamer}-devel
BuildRequires:  %{gstreamer}-plugins-base-devel
BuildRequires:  %{gstreamer}-plugins-good-devel
BuildRequires:  %{gstreamer}-plugins-bad-devel

%description
GStreamer plug-in to handle DASH common encryption

%prep
%setup -q -n gst-cenc-%{version}

%build
%configure
make

%install
rm -rf $RPM_BUILD_ROOT
%makeinstall

# Remove unneeded .la and .a files
rm -rf $RPM_BUILD_ROOT%{_libdir}/gstreamer-%{majorminor}/*.a
rm -rf $RPM_BUILD_ROOT%{_libdir}/gstreamer-%{majorminor}/*.la

%clean
rm -rf $RPM_BUILD_ROOT

%files
%defattr(-,root,root)
%doc README.md
%{_libdir}/gstreamer-%{majorminor}/*.so

%changelog

